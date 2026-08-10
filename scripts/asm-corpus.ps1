#Requires -Version 5.1
<#
.SYNOPSIS
Builds the ASM_PLAN.md Phase 0 corpus: the input pairs an assembly kernel must
be measured against before it can be merged.

.DESCRIPTION
Each pair is written as <CorpusRoot>\<name>\old.bin plus new.bin, the layout
BenchmarkGenerateCorpus and TestZZCorpusProbe expect.

Binaries built here are pinned to GOAMD64=v1, GOEXPERIMENT=none, CGO_ENABLED=0,
-trimpath and -buildvcs=false, and GOFLAGS is cleared, so rebuilding reproduces
the same corpus instead of inheriting whatever the shell had set.

Pairs that need files this machine does not have (v1.exe/v2.exe, the Go
toolchain binaries) are skipped with a warning rather than failing the run.

.EXAMPLE
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\asm-corpus.ps1

.EXAMPLE
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\asm-corpus.ps1 -Include '0[12]' -Force
#>
[CmdletBinding()]
param(
    # Destination for the corpus. Defaults to <repo>\.asmbench\corpus.
    [string]$CorpusRoot,

    # Older revision used for the real-update pairs.
    [string]$BaseRevision = 'HEAD~5',

    # Newer revision used for the real-update pairs.
    [string]$HeadRevision = 'HEAD',

    # Regex filter over pair names; default builds every pair.
    [string]$Include = '.',

    # Rebuild pairs that already exist.
    [switch]$Force
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repoRoot = Split-Path -Parent $PSScriptRoot
if (-not $CorpusRoot) {
    $CorpusRoot = Join-Path $repoRoot '.asmbench\corpus'
}
$workRoot = Join-Path $repoRoot '.asmbench\corpus-work'
$generator = Join-Path $PSScriptRoot 'asmcorpus.go'

function Invoke-Tool {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string[]]$Arguments
    )
    Write-Verbose ('run: {0} {1}' -f $Path, ($Arguments -join ' '))
    & $Path @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw ('{0} {1} failed with exit code {2}' -f $Path, ($Arguments -join ' '), $LASTEXITCODE)
    }
}

function Format-Invariant {
    param([Parameter(Mandatory)][double]$Value)
    return $Value.ToString([System.Globalization.CultureInfo]::InvariantCulture)
}

# Get-Sha256 hashes through .NET rather than Get-FileHash, which is not present
# on every PowerShell 5.1 install, and streams so a 28 MB input is not buffered.
function Get-Sha256 {
    param([Parameter(Mandatory)][string]$Path)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $stream = [System.IO.File]::OpenRead($Path)
        try {
            return [System.BitConverter]::ToString($sha.ComputeHash($stream)).Replace('-', '').ToLowerInvariant()
        } finally {
            $stream.Dispose()
        }
    } finally {
        $sha.Dispose()
    }
}

# Build-Image cross-compiles one module. GOOS is scoped to the call so the
# generator, which runs natively, is never invoked under a foreign GOOS.
function Build-Image {
    param(
        [Parameter(Mandatory)][string]$ModuleDir,
        [Parameter(Mandatory)][string]$Package,
        [Parameter(Mandatory)][string]$Output,
        [Parameter(Mandatory)][string]$Goos
    )
    $previousGoos = $env:GOOS
    $env:GOOS = $Goos
    try {
        Invoke-Tool -Path 'go' -Arguments @(
            'build', '-C', $ModuleDir, '-trimpath', '-buildvcs=false', '-o', $Output, $Package
        )
    } finally {
        $env:GOOS = $previousGoos
    }
}

function New-SyntheticPair {
    param(
        [Parameter(Mandatory)][string]$PairDir,
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][int]$Functions,
        [Parameter(Mandatory)][double]$Churn,
        [Parameter(Mandatory)][int]$Insert,
        [Parameter(Mandatory)][int]$Seed,
        [Parameter(Mandatory)][string]$Goos,
        [switch]$Repetitive
    )
    $sourceRoot = Join-Path $workRoot $Name
    if (Test-Path $sourceRoot) { Remove-Item -Recurse -Force $sourceRoot }

    foreach ($variant in 0, 1) {
        $variantDir = Join-Path $sourceRoot ('v{0}' -f $variant)
        $arguments = @(
            'run', $generator,
            '-out', $variantDir,
            '-functions', $Functions,
            '-seed', $Seed,
            '-variant', $variant,
            '-churn', (Format-Invariant $Churn),
            '-insert', $Insert
        )
        if ($Repetitive) { $arguments += '-repetitive' }
        Invoke-Tool -Path 'go' -Arguments $arguments
    }

    Build-Image -ModuleDir (Join-Path $sourceRoot 'v0') -Package '.' -Goos $Goos -Output (Join-Path $PairDir 'old.bin')
    Build-Image -ModuleDir (Join-Path $sourceRoot 'v1') -Package '.' -Goos $Goos -Output (Join-Path $PairDir 'new.bin')
}

# New-RevisionPair builds one package at two revisions in detached worktrees, so
# the pair reflects a real update and never depends on the dirty working tree.
function New-RevisionPair {
    param(
        [Parameter(Mandatory)][string]$PairDir,
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string]$Package,
        [Parameter(Mandatory)][string]$Goos
    )
    $worktrees = @()
    try {
        foreach ($side in @(
                @{ Key = 'old.bin'; Revision = $BaseRevision },
                @{ Key = 'new.bin'; Revision = $HeadRevision }
            )) {
            $treeDir = Join-Path $workRoot ('{0}-{1}' -f $Name, $side.Key.Replace('.bin', ''))
            if (Test-Path $treeDir) { Invoke-Tool -Path 'git' -Arguments @('worktree', 'remove', '--force', $treeDir) }
            Invoke-Tool -Path 'git' -Arguments @('worktree', 'add', '--detach', $treeDir, $side.Revision)
            $worktrees += $treeDir
            Build-Image -ModuleDir $treeDir -Package $Package -Goos $Goos -Output (Join-Path $PairDir $side.Key)
        }
    } finally {
        foreach ($treeDir in $worktrees) {
            & git worktree remove --force $treeDir 2>$null | Out-Null
        }
    }
}

function Copy-ExistingPair {
    param(
        [Parameter(Mandatory)][string]$PairDir,
        [Parameter(Mandatory)][string]$OldPath,
        [Parameter(Mandatory)][string]$NewPath
    )
    Copy-Item -LiteralPath $OldPath -Destination (Join-Path $PairDir 'old.bin') -Force
    Copy-Item -LiteralPath $NewPath -Destination (Join-Path $PairDir 'new.bin') -Force
}

# Pin the toolchain settings the plan measures against. Restored on exit so an
# interactive shell is not left reconfigured.
$savedEnvironment = @{}
foreach ($key in 'GOAMD64', 'GOEXPERIMENT', 'CGO_ENABLED', 'GOFLAGS', 'GOOS', 'GOARCH') {
    $savedEnvironment[$key] = [Environment]::GetEnvironmentVariable($key)
}
$env:GOAMD64 = 'v1'
$env:GOEXPERIMENT = 'none'
$env:CGO_ENABLED = '0'
$env:GOFLAGS = ''
$env:GOARCH = 'amd64'

try {
    $goRoot = (& go env GOROOT).Trim()
    $goVersion = (& go version).Trim()
    $baseSha = (& git rev-parse --short $BaseRevision).Trim()
    $headSha = (& git rev-parse --short $HeadRevision).Trim()

    New-Item -ItemType Directory -Force -Path $CorpusRoot, $workRoot | Out-Null

    $definitions = @(
        @{
            Name        = '01-small-pe-localized'
            Description = 'small synthetic PE, 2% of bodies rewritten, 4 functions inserted'
            Build       = { param($dir) New-SyntheticPair -PairDir $dir -Name '01-small-pe-localized' -Functions 500 -Churn 0.02 -Insert 4 -Seed 1 -Goos 'windows' }
        },
        @{
            Name        = '02-medium-pe-update'
            Description = ('real go-zucchini PE update {0} -> {1}' -f $baseSha, $headSha)
            Build       = { param($dir) New-RevisionPair -PairDir $dir -Name '02-medium-pe-update' -Package './cmd/zucchini' -Goos 'windows' }
        },
        @{
            Name        = '03-medium-elf-update'
            Description = ('real go-zucchini ELF update {0} -> {1}' -f $baseSha, $headSha)
            Build       = { param($dir) New-RevisionPair -PairDir $dir -Name '03-medium-elf-update' -Package './cmd/zucchini' -Goos 'linux' }
        },
        @{
            Name        = '04-large-pe-release'
            Description = 'large real PE release pair (v1.exe -> v2.exe)'
            Build       = {
                param($dir)
                $old = Join-Path $repoRoot 'v1.exe'
                $new = Join-Path $repoRoot 'v2.exe'
                if (-not (Test-Path $old) -or -not (Test-Path $new)) {
                    throw 'skip: v1.exe and v2.exe are not present in the repository root'
                }
                Copy-ExistingPair -PairDir $dir -OldPath $old -NewPath $new
            }
        },
        @{
            Name        = '05-adversarial-repetitive-elf'
            Description = 'synthetic ELF with heavily repeated bodies, stresses repeated suffixes'
            Build       = { param($dir) New-SyntheticPair -PairDir $dir -Name '05-adversarial-repetitive-elf' -Functions 1500 -Churn 0.05 -Insert 8 -Seed 7 -Goos 'linux' -Repetitive }
        },
        @{
            Name        = '06-low-similarity-pe'
            Description = 'unrelated PE pair (gofmt.exe -> go.exe), worst case for the matcher'
            Build       = {
                param($dir)
                $old = Join-Path $goRoot 'bin\gofmt.exe'
                $new = Join-Path $goRoot 'bin\go.exe'
                if (-not (Test-Path $old) -or -not (Test-Path $new)) {
                    throw 'skip: the Go toolchain binaries were not found under GOROOT\bin'
                }
                Copy-ExistingPair -PairDir $dir -OldPath $old -NewPath $new
            }
        }
    )

    $records = @()
    foreach ($definition in $definitions) {
        $name = $definition.Name
        if ($name -notmatch $Include) {
            Write-Verbose ('skip {0}: excluded by -Include' -f $name)
            continue
        }

        $pairDir = Join-Path $CorpusRoot $name
        $oldPath = Join-Path $pairDir 'old.bin'
        $newPath = Join-Path $pairDir 'new.bin'

        if ((Test-Path $oldPath) -and (Test-Path $newPath) -and -not $Force) {
            Write-Host ('present  {0}' -f $name)
        } else {
            Write-Host ('building {0} ...' -f $name)
            if (Test-Path $pairDir) { Remove-Item -Recurse -Force $pairDir }
            New-Item -ItemType Directory -Force -Path $pairDir | Out-Null
            try {
                & $definition.Build $pairDir
            } catch {
                Remove-Item -Recurse -Force $pairDir -ErrorAction SilentlyContinue
                Write-Warning ('{0}: {1}' -f $name, $_.Exception.Message)
                continue
            }
        }

        $oldItem = Get-Item -LiteralPath $oldPath
        $newItem = Get-Item -LiteralPath $newPath
        $records += [ordered]@{
            name        = $name
            description = $definition.Description
            oldBytes    = $oldItem.Length
            newBytes    = $newItem.Length
            oldSHA256   = Get-Sha256 -Path $oldPath
            newSHA256   = Get-Sha256 -Path $newPath
        }
    }

    if ($records.Count -eq 0) {
        throw 'no corpus pairs were produced'
    }

    $manifest = [ordered]@{
        generatedUtc = (Get-Date).ToUniversalTime().ToString('o')
        goVersion    = $goVersion
        goamd64      = 'v1'
        goexperiment = 'none'
        cgoEnabled   = '0'
        buildFlags   = '-trimpath -buildvcs=false'
        baseRevision = ('{0} ({1})' -f $BaseRevision, $baseSha)
        headRevision = ('{0} ({1})' -f $HeadRevision, $headSha)
        cpu          = (Get-CimInstance Win32_Processor | Select-Object -First 1 -ExpandProperty Name).Trim()
        os           = [Environment]::OSVersion.VersionString
        pairs        = $records
    }
    $manifestPath = Join-Path $CorpusRoot 'manifest.json'
    $manifest | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $manifestPath -Encoding UTF8

    Write-Host ''
    Write-Host ('corpus: {0}' -f $CorpusRoot)
    $records |
        ForEach-Object {
            [pscustomobject]@{
                Pair    = $_.name
                OldMiB  = [math]::Round($_.oldBytes / 1MB, 2)
                NewMiB  = [math]::Round($_.newBytes / 1MB, 2)
                Details = $_.description
            }
        } |
        Format-Table -AutoSize |
        Out-String |
        Write-Host
    Write-Host ('{0} pair(s) ready; manifest written to {1}' -f $records.Count, $manifestPath)
    if ($records.Count -lt 5) {
        Write-Warning 'ASM_PLAN.md Phase 0 requires at least five pairs; some were skipped.'
    }
} finally {
    foreach ($key in $savedEnvironment.Keys) {
        [Environment]::SetEnvironmentVariable($key, $savedEnvironment[$key])
    }
}