package main

import (
	"encoding/hex"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"os"

	"github.com/404Setup/go-zucchini"
	"github.com/404Setup/go-zucchini/internal/filemap"
	"github.com/404Setup/go-zucchini/internal/matcher"
	"github.com/404Setup/go-zucchini/internal/patch"
	"github.com/404Setup/go-zucchini/internal/sais"
	"github.com/404Setup/go-zucchini/internal/types"
)

func main() {
	os.Exit(int(runCLI(os.Args[1:], os.Stdout, os.Stderr)))
}

func runCLI(args []string, stdout, stderr io.Writer) zucchini.StatusCode {
	command, err := parseCommandLine(args)
	if err != nil {
		fmt.Fprintf(stderr, "Error: %v\n\n", err)
		printUsage(stderr)
		return zucchini.StatusInvalidParam
	}
	if command.version {
		fmt.Fprintln(stdout, "Zucchini 2.0")
		return zucchini.StatusSuccess
	}
	if command.help {
		if command.spec == nil {
			printUsage(stdout)
		} else {
			printCommandUsage(stdout, command.spec)
		}
		return zucchini.StatusSuccess
	}

	switch command.spec.name {
	case "gen":
		return runGen(command, stderr)
	case "apply":
		return runApply(command, stderr)
	case "verify":
		return runVerify(command, stderr)
	case "read":
		return runRead(command, stdout, stderr)
	case "detect":
		return runDetect(command, stdout, stderr)
	case "match":
		return runMatch(command, stdout, stderr)
	case "crc32":
		return runCrc32(command, stdout, stderr)
	case "suffix-array":
		return runSuffixArray(command, stderr)
	default:
		return zucchini.StatusInvalidParam
	}
}

func runGen(command *parsedCommand, stderr io.Writer) zucchini.StatusCode {
	oldFile, newFile, patchFile := command.positional[0], command.positional[1], command.positional[2]
	if filemap.SameFile(patchFile, oldFile) || filemap.SameFile(patchFile, newFile) {
		fmt.Fprintln(stderr, "Error: patch_file must be different from both input files.")
		return zucchini.StatusInvalidParam
	}
	err := zucchini.GenerateFileWithOptions(oldFile, newFile, patchFile, zucchini.GenerateFileOptions{
		Raw: command.has("raw"), ImposedMatches: command.value("impose"), KeepPartialOutput: command.has("keep"),
	})
	if err != nil {
		fmt.Fprintf(stderr, "GenerateFile failed: %v\n", err)
		return statusFromError(err, zucchini.StatusFatal)
	}
	return zucchini.StatusSuccess
}

func runApply(command *parsedCommand, stderr io.Writer) zucchini.StatusCode {
	oldFile, patchFile, newFile := command.positional[0], command.positional[1], command.positional[2]
	if filemap.SameFile(newFile, oldFile) || filemap.SameFile(newFile, patchFile) {
		fmt.Fprintln(stderr, "Error: new_file must be different from both input files.")
		return zucchini.StatusInvalidParam
	}
	var expectedSHA256 []byte
	if encoded := command.value("sha256"); encoded != "" {
		var err error
		expectedSHA256, err = hex.DecodeString(encoded)
		if err != nil || len(expectedSHA256) != 32 {
			fmt.Fprintln(stderr, "Error: --sha256 must be exactly 64 hexadecimal characters.")
			return zucchini.StatusInvalidParam
		}
	}
	if err := zucchini.ApplyFileWithOptions(oldFile, patchFile, newFile, zucchini.ApplyFileOptions{
		KeepPartialOutput: command.has("keep"), ExpectedNewSHA256: expectedSHA256,
	}); err != nil {
		fmt.Fprintf(stderr, "ApplyFile failed: %v\n", err)
		return statusFromError(err, zucchini.StatusFatal)
	}

	return zucchini.StatusSuccess
}

func statusFromError(err error, fallback zucchini.StatusCode) zucchini.StatusCode {
	var zucchiniErr *zucchini.Error
	if errors.As(err, &zucchiniErr) {
		return zucchiniErr.Code
	}
	return fallback
}

func runVerify(command *parsedCommand, stderr io.Writer) (result zucchini.StatusCode) {
	patchFile := command.positional[0]
	mapping, code := openMappedInput(patchFile, "patch_file", stderr)
	if code != zucchini.StatusSuccess {
		return code
	}
	defer closeMappedInput(mapping, patchFile, stderr, &result)

	_, ok := patch.CreateEnsemblePatchReader(mapping.Data)
	if !ok {
		fmt.Fprintln(stderr, "Fatal error found when verifying patch.")
		return zucchini.StatusPatchReadError
	}
	return zucchini.StatusSuccess
}

func runRead(command *parsedCommand, stdout, stderr io.Writer) (result zucchini.StatusCode) {
	exeFile := command.positional[0]
	mapping, code := openMappedInput(exeFile, "executable", stderr)
	if code != zucchini.StatusSuccess {
		return code
	}
	defer closeMappedInput(mapping, exeFile, stderr, &result)
	data := mapping.Data

	disasmObj := matcher.MakeDisassemblerWithoutFallback(data)
	if disasmObj == nil {
		fmt.Fprintf(stdout, "File %s is not a recognized executable binary format.\n", exeFile)
		return zucchini.StatusSuccess
	}

	fmt.Fprintf(stdout, "Detected Executable: %s (%s, %d bytes)\n", exeFile, disasmObj.GetExeTypeString(), disasmObj.Size())
	groups := disasmObj.MakeReferenceGroups()
	fmt.Fprintf(stdout, "Reference Groups (%d):\n", len(groups))

	for i, group := range groups {
		fmt.Fprintf(stdout, "  Group [%d]: TypeTag=%d, PoolTag=%d, Width=%d\n", i, group.TypeTag(), group.PoolTag(), group.Width())
		if command.has("dump") {
			reader := group.GetReader(0, zucchini.Offset(len(data)))
			for {
				ref, ok := reader.GetNext()
				if !ok {
					break
				}
				fmt.Fprintf(stdout, "    Ref: Location=0x%X, Target=0x%X\n", ref.Location, ref.Target)
			}
		}
	}

	return zucchini.StatusSuccess
}

func runDetect(command *parsedCommand, stdout, stderr io.Writer) (result zucchini.StatusCode) {
	archiveFile := command.positional[0]
	mapping, code := openMappedInput(archiveFile, "archive_file", stderr)
	if code != zucchini.StatusSuccess {
		return code
	}
	defer closeMappedInput(mapping, archiveFile, stderr, &result)

	finder := matcher.NewElementFinder(mapping.Data, matcher.DetectElementFromDisassembler)
	count := 0
	for {
		elem, ok := finder.GetNext()
		if !ok {
			break
		}
		fmt.Fprintf(stdout, "  Element [%d]: Type=%s, Offset=0x%X, Size=%d\n",
			count, elem.ExeType.String(), elem.Region.Offset, elem.Region.Size)
		count++
	}

	return zucchini.StatusSuccess
}

func runMatch(command *parsedCommand, stdout, stderr io.Writer) (result zucchini.StatusCode) {
	oldFile, newFile := command.positional[0], command.positional[1]
	oldMapping, code := openMappedInput(oldFile, "old_file", stderr)
	if code != zucchini.StatusSuccess {
		return code
	}
	defer closeMappedInput(oldMapping, oldFile, stderr, &result)
	newMapping, code := openMappedInput(newFile, "new_file", stderr)
	if code != zucchini.StatusSuccess {
		return code
	}
	defer closeMappedInput(newMapping, newFile, stderr, &result)

	if imposedMatches := command.value("impose"); imposedMatches != "" {
		m := matcher.NewImposedEnsembleMatcher(imposedMatches)
		if !m.RunMatch(oldMapping.Data, newMapping.Data) {
			fmt.Fprintln(stderr, "RunMatch() failed.")
			return zucchini.StatusFatal
		}
		printMatchResults(stdout, oldFile, newFile, m.Matches(), m.NumIdentical())
	} else {
		m := matcher.NewHeuristicEnsembleMatcher()
		if !m.RunMatch(oldMapping.Data, newMapping.Data) {
			fmt.Fprintln(stderr, "RunMatch() failed.")
			return zucchini.StatusFatal
		}
		printMatchResults(stdout, oldFile, newFile, m.Matches(), m.NumIdentical())
	}
	return zucchini.StatusSuccess
}

func printMatchResults(stdout io.Writer, oldFile, newFile string, matches []types.ElementMatch, identical int) {
	fmt.Fprintf(stdout, "Matching results between %s and %s:\n", oldFile, newFile)
	fmt.Fprintf(stdout, "  Identical elements skipped: %d\n", identical)
	fmt.Fprintf(stdout, "  Nontrivial matched pairs:  %d\n", len(matches))
	for i, matchPair := range matches {
		fmt.Fprintf(stdout, "  Match [%d]: Type=%s\n", i, matchPair.OldElement.ExeType.String())
		fmt.Fprintf(stdout, "    Old: Offset=0x%X, Size=%d\n", matchPair.OldElement.Region.Offset, matchPair.OldElement.Region.Size)
		fmt.Fprintf(stdout, "    New: Offset=0x%X, Size=%d\n", matchPair.NewElement.Region.Offset, matchPair.NewElement.Region.Size)
	}
}

func runCrc32(command *parsedCommand, stdout, stderr io.Writer) (result zucchini.StatusCode) {
	file := command.positional[0]
	mapping, code := openMappedInput(file, "file", stderr)
	if code != zucchini.StatusSuccess {
		return code
	}
	defer closeMappedInput(mapping, file, stderr, &result)
	fmt.Fprintf(stdout, "CRC32: %08X\n", crc32.ChecksumIEEE(mapping.Data))
	return zucchini.StatusSuccess
}

func runSuffixArray(command *parsedCommand, stderr io.Writer) (result zucchini.StatusCode) {
	file := command.positional[0]
	mapping, code := openMappedInput(file, "file", stderr)
	if code != zucchini.StatusSuccess {
		return code
	}
	defer closeMappedInput(mapping, file, stderr, &result)
	_ = sais.MakeSuffixArray(mapping.Data, 256)
	return zucchini.StatusSuccess
}

func openMappedInput(path, label string, stderr io.Writer) (*filemap.Mapping, zucchini.StatusCode) {
	mapping, err := filemap.Open(path)
	if err != nil {
		fmt.Fprintf(stderr, "Error reading %s %s: %v\n", label, path, err)
		return nil, zucchini.StatusFileReadError
	}
	return mapping, zucchini.StatusSuccess
}

func closeMappedInput(mapping *filemap.Mapping, path string, stderr io.Writer, result *zucchini.StatusCode) {
	if err := mapping.Close(); err != nil && *result == zucchini.StatusSuccess {
		fmt.Fprintf(stderr, "Error closing file %s: %v\n", path, err)
		*result = zucchini.StatusIoError
	}
}
