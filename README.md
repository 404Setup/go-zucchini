# go-zucchini

`go-zucchini` is a pure Go port of Chromium's Zucchini binary diff algorithm.
It provides a command-line tool and a Go package for generating and applying
Zucchini patches without Chromium, C++, cgo, or external Go modules.

## Features

- Generates and applies Chromium-compatible Zucchini patches.
- Uses executable-aware matching for supported PE and ELF images.
- Falls back to raw binary matching for unrecognized data.
- Memory-maps files on Unix. Default Windows builds use ordinary file I/O and
  exclude the project's `unsafe` writable-mapping backend.
- Supports in-memory and caller-provided output buffers.
- Builds with the Go standard library only.

## Requirements

- Go 1.26.5 or later.
- Windows, Linux, macOS, or another Unix platform covered by the file-mapping
  implementation.

## Installation

Install the command-line tool:

```bash
go install github.com/404Setup/go-zucchini/cmd/zucchini@latest
```

Or build it from a checkout:

```bash
go build -o zucchini ./cmd/zucchini
```

For a standard Windows release build, use:

```powershell
.\scripts\build-windows.ps1
```

The script disables inherited experiments and linker stripping, targets the
baseline amd64 instruction set, preserves Go/VCS build metadata, and writes a
SHA-256 checksum next to the executable.

Tagged and manually dispatched GitHub builds also attach signed build
provenance to the Windows executable. Verify a downloaded release artifact:

```powershell
Get-FileHash .\zucchini.exe -Algorithm SHA256
gh attestation verify .\zucchini.exe --repo 404Setup/go-zucchini
go version -m .\zucchini.exe
```

## Command-line usage

Generate and apply a patch:

```bash
zucchini gen old.bin new.bin update.patch
zucchini apply old.bin update.patch reconstructed.bin
zucchini apply old.bin update.patch reconstructed.bin --sha256 <trusted-output-sha256>
```

Available commands:

```text
gen            Generate a patch
apply          Apply a patch
verify         Validate a patch
read           Inspect executable references
detect         Detect embedded executables
match          Match executable elements
crc32          Calculate CRC32
suffix-array   Build a suffix array
```

Run `zucchini help` or `zucchini <command> --help` for command syntax. The
legacy `-gen` and `-apply` command forms are also accepted.

Generation options:

- `--raw` disables executable-aware matching.
- `--impose <matches>` supplies explicit element matches in
  `old_offset+old_size=new_offset+new_size` form.
- `--keep` retains a partial output file after an error.

## Go package

Add the module:

```bash
go get github.com/404Setup/go-zucchini
```

Use the file-oriented API for large inputs:

```go
package main

import (
	"log"

	zucchini "github.com/404Setup/go-zucchini"
)

func main() {
	if err := zucchini.GenerateFile("old.bin", "new.bin", "update.patch"); err != nil {
		log.Fatal(err)
	}
	if err := zucchini.ApplyFile("old.bin", "update.patch", "reconstructed.bin"); err != nil {
		log.Fatal(err)
	}
}
```

For data already in memory:

```go
patch, err := zucchini.GenerateBuffer(oldImage, newImage)
if err != nil {
	return err
}
reconstructed, err := zucchini.Apply(oldImage, patch)
```

`ApplyTo` writes into a caller-provided buffer. `GenerateFileWithOptions` and
`ApplyFileWithOptions` expose raw matching, imposed matches, and partial-output
retention. File-backed apply writes to a same-directory temporary file and only
installs it after CRC and optional trusted SHA-256 verification succeed.
`GenerateFile` streams patch serialization to a temporary file in
the destination directory, flushes and verifies its size, then atomically
replaces the destination. Failed generation leaves an existing destination
untouched unless partial-output retention is explicitly requested.

## Supported executable formats

Executable-aware matching currently supports:

- Windows PE: x86 and x86-64.
- ELF: x86, x86-64, ARM, and AArch64.

The PE parser validates both the optional-header format and COFF machine type.
Other architectures are handled as raw data instead of being interpreted as
x86-64. DEX and Zucchini Text Format are not implemented.

## Profiling and PGO

`BenchmarkGenerateFile` is the representative profile entry point for patch
generation. Collect profiles from production-like inputs:

```bash
ZUCCHINI_BENCH_OLD=old.bin ZUCCHINI_BENCH_NEW=new.bin \
  go test -run '^$' -bench '^BenchmarkGenerateFile$' -benchtime=1x \
  -cpuprofile=cpu.pprof
go build -pgo=off -o zucchini-baseline ./cmd/zucchini
go build -pgo=cpu.pprof -o zucchini-pgo ./cmd/zucchini
```

Compare end-to-end generation on several representative files before adopting
a profile. Promote it to `cmd/zucchini/default.pgo` only when the improvement is
stable across the intended workload.

## Development

Run the test suite and static checks:

```bash
go test ./...
go vet ./...
```

On Windows, use the pinned test entry point so machine-level Go experiments,
instruction targets, and cgo settings cannot silently change the test
executables inspected by security software:

```powershell
.\scripts\test-windows.ps1
go vet ./...
```

The large memory and assembly corpus probes are intentionally absent from the
default test executable. Enable them only for their dedicated measurement
workflows with `-tags zucchini_memprobe` or `-tags zucchini_asmcorpus`.

The implementation includes randomized SA-IS tests, patch validation tests,
generate/apply symmetry tests, and file-mapping tests. Large local PE fixtures
enable additional memory and compatibility probes when present.

## Patch trust model

Applying a patch never starts the reconstructed file, invokes a shell, or uses
the network. However, the Zucchini format's CRC32 fields only detect accidental
corruption; they do not authenticate a patch or its output. An attacker who can
replace a patch can construct a patch for attacker-chosen output when the old
file is known. Authenticate patches with a signature, or pass a SHA-256 digest
obtained through a trusted channel via `apply --sha256` or
`ApplyFileOptions.ExpectedNewSHA256`, before executing or distributing output.

## License and attribution

This project is derived from Chromium's Zucchini implementation and is
distributed under the BSD 3-Clause license in [LICENSE](LICENSE). See
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) for upstream attribution.
