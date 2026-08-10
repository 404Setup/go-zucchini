//go:build ignore

// asmcorpus generates a self-contained Go module whose compiled binary is a
// deterministic stand-in for a real executable: many small functions, plenty of
// intra-module calls, and package-level state, so the compiled output contains
// the relocated code references that Zucchini's matcher actually works on.
//
// Two invocations with the same -seed and -functions produce byte-identical
// source. Changing -variant rewrites a controlled fraction of the function
// bodies and shifts later function offsets, which is what an update looks like
// to the patcher.
//
// Usage:
//
//	go run scripts/asmcorpus.go -out DIR -functions N -seed S -variant V -churn F
package main

import (
	"flag"
	"fmt"
	"hash/fnv"
	"log"
	"math/rand"
	"os"
	"path/filepath"
	"strings"
)

func main() {
	out := flag.String("out", "", "directory to write the generated module into (required)")
	functions := flag.Int("functions", 1500, "number of generated functions")
	seed := flag.Int64("seed", 1, "base seed shared by every variant of the same corpus pair")
	variant := flag.Int("variant", 0, "variant index; 0 is the old image, 1 the new image")
	churn := flag.Float64("churn", 0.05, "fraction of function bodies rewritten in variant 1")
	insert := flag.Int("insert", 8, "functions inserted in variant 1 to shift later code offsets")
	repetitive := flag.Bool("repetitive", false, "emit near-identical bodies to stress repeated suffixes")
	perFile := flag.Int("per-file", 250, "generated functions per source file")
	flag.Parse()

	if *out == "" {
		log.Fatal("-out is required")
	}
	if *functions <= 0 || *perFile <= 0 {
		log.Fatal("-functions and -per-file must be positive")
	}
	if err := generate(*out, options{
		functions:  *functions,
		seed:       *seed,
		variant:    *variant,
		churn:      *churn,
		insert:     *insert,
		repetitive: *repetitive,
		perFile:    *perFile,
	}); err != nil {
		log.Fatal(err)
	}
}

type options struct {
	functions  int
	seed       int64
	variant    int
	churn      float64
	insert     int
	repetitive bool
	perFile    int
}

func generate(out string, opt options) error {
	if err := os.MkdirAll(out, 0o755); err != nil {
		return err
	}

	total := opt.functions
	if opt.variant != 0 {
		total += opt.insert
	}

	files := map[string]string{
		"go.mod":  "module asmcorpus\n\ngo 1.24\n",
		"main.go": mainSource(total),
	}
	for start := 0; start < total; start += opt.perFile {
		end := min(start+opt.perFile, total)
		name := fmt.Sprintf("gen%03d.go", start/opt.perFile)
		files[name] = fileSource(start, end, opt)
	}

	for name, content := range files {
		if err := os.WriteFile(filepath.Join(out, name), []byte(content), 0o644); err != nil {
			return err
		}
	}
	return nil
}

func mainSource(total int) string {
	var b strings.Builder
	b.WriteString("package main\n\nimport (\n\t\"fmt\"\n\t\"os\"\n)\n\n")
	b.WriteString("// state is package-level so the generated functions produce loads and\n")
	b.WriteString("// stores against absolute addresses rather than being folded away.\n")
	b.WriteString("var state [64]uint64\n\n")
	b.WriteString("func main() {\n")
	b.WriteString("\tvar acc uint64\n")
	b.WriteString("\tfor i, fn := range table {\n")
	b.WriteString("\t\tacc += fn(uint64(i) + acc)\n")
	b.WriteString("\t}\n")
	b.WriteString("\tif len(os.Args) > 1 {\n")
	b.WriteString("\t\tfmt.Println(acc, state[acc%uint64(len(state))])\n")
	b.WriteString("\t}\n")
	b.WriteString("}\n\n")
	b.WriteString("// table keeps every generated function reachable so the linker cannot\n")
	b.WriteString("// discard them, and it emits a large relocated pointer array.\n")
	b.WriteString(fmt.Sprintf("var table = [%d]func(uint64) uint64{\n", total))
	for i := range total {
		b.WriteString(fmt.Sprintf("\tfn%06d,\n", i))
	}
	b.WriteString("}\n\n")
	b.WriteString("// mix0 and mix1 are called from the generated bodies so the image also\n")
	b.WriteString("// contains ordinary intra-module call references, not only the pointer\n")
	b.WriteString("// table. Both are marked noinline for the same reason.\n")
	b.WriteString("//go:noinline\nfunc mix0(v uint64) uint64 { return v*0x9E3779B97F4A7C15 + 0x165667B1 }\n\n")
	b.WriteString("//go:noinline\nfunc mix1(v uint64) uint64 { return v ^ (v >> 29) ^ state[v%uint64(len(state))] }\n")
	return b.String()
}

func fileSource(start, end int, opt options) string {
	var b strings.Builder
	b.WriteString("package main\n\n")
	for index := start; index < end; index++ {
		b.WriteString(functionSource(index, opt))
		b.WriteByte('\n')
	}
	return b.String()
}

// functionSource derives each body from its own seed so that a variant can
// rewrite one function without disturbing any other.
func functionSource(index int, opt options) string {
	seed := opt.seed
	if opt.repetitive {
		seed += int64(index % 4)
	} else {
		seed += int64(index)
	}
	if opt.variant != 0 && rewritten(index, opt) {
		seed = -seed - 1
	}
	rng := rand.New(rand.NewSource(seed))

	var b strings.Builder
	fmt.Fprintf(&b, "func fn%06d(v uint64) uint64 {\n", index)
	statements := 4 + rng.Intn(6)
	for range statements {
		switch rng.Intn(6) {
		case 0:
			fmt.Fprintf(&b, "\tv = v*%d + %d\n", rng.Uint64()|1, rng.Uint64())
		case 1:
			fmt.Fprintf(&b, "\tv ^= v>>%d | %d\n", 1+rng.Intn(31), rng.Uint64())
		case 2:
			fmt.Fprintf(&b, "\tstate[%d] += v\n", rng.Intn(64))
		case 3:
			fmt.Fprintf(&b, "\tif v&%d != 0 {\n\t\tv += %d\n\t} else {\n\t\tv -= %d\n\t}\n", rng.Uint64(), rng.Uint64(), rng.Uint64())
		case 4:
			fmt.Fprintf(&b, "\tv += state[%d] ^ %d\n", rng.Intn(64), rng.Uint64())
		default:
			fmt.Fprintf(&b, "\tv = v<<%d | v>>%d\n", 1+rng.Intn(31), 1+rng.Intn(31))
		}
	}
	fmt.Fprintf(&b, "\treturn mix%d(v) + %d\n}\n", rng.Intn(2), rng.Uint64())
	return b.String()
}

// rewritten selects a stable pseudorandom subset of indices, so the churn
// fraction is reproducible without depending on iteration order.
func rewritten(index int, opt options) bool {
	digest := fnv.New32a()
	fmt.Fprintf(digest, "%d:%d", opt.seed, index)
	return float64(digest.Sum32()%10_000)/10_000 < opt.churn
}
