#Requires -Version 5.1
<#
.SYNOPSIS
Runs the ASM_PLAN.md Phase 0 interleaved comparison between the reference build
and an experimental assembly build.

.DESCRIPTION
Two test binaries are compiled once with the zucchini_asmcorpus probe tag: a
baseline with no kernel tag and a candidate with -tags asmcompare. Every pair
runs in a fresh process, with its baseline and candidate samples adjacent, so
earlier large pairs cannot retain heap or runtime state that contaminates later
measurements.

Interleaving is per sample, not per configuration: sample 1 baseline, sample 1
candidate, sample 2 baseline, and so on. Medians are reported because a single
slow sample from background activity must not decide a release gate.

The corpus must already exist; build it with scripts\asm-corpus.ps1 first.

.EXAMPLE
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\asm-bench.ps1

.EXAMPLE
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\asm-bench.ps1 -Samples 10 -Tags asmcompare
#>
[CmdletBinding()]
param(
    # Corpus produced by scripts\asm-corpus.ps1. Defaults to <repo>\.asmbench\corpus.
    [string]$CorpusRoot,

    # Build tags selecting the candidate kernel.
    [string]$Tags = 'asmcompare',

    # Optional prebuilt baseline test binary. This allows a new pure-Go
    # candidate to be compared with an immutable binary from an earlier run.
    [string]$BaselineBinary,

    # Interleaved samples per configuration. ASM_PLAN.md Phase 0 requires ten.
    [int]$Samples = 10,

    # Regex filter over corpus pair names.
    [string]$Include = '.',

    # Directory for test binaries, raw output, and the JSON result.
    [string]$OutputRoot,

    # Omit the per-pair baseline CPU profiles. Profiles are collected by
    # default because ASM_PLAN.md Phase 0 requires one for every corpus pair.
    [switch]$SkipCpuProfiles
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repoRoot = Split-Path -Parent $PSScriptRoot
if (-not $CorpusRoot) { $CorpusRoot = Join-Path $repoRoot '.asmbench\corpus' }
if (-not $OutputRoot) { $OutputRoot = Join-Path $repoRoot '.asmbench\bench' }

if (-not (Test-Path -LiteralPath $CorpusRoot)) {
    throw ('corpus not found at {0}; run scripts\asm-corpus.ps1 first' -f $CorpusRoot)
}
if ($Samples -lt 1) { throw '-Samples must be at least 1' }

New-Item -ItemType Directory -Force -Path $OutputRoot | Out-Null
$OutputRoot = (Resolve-Path -LiteralPath $OutputRoot).Path
$benchGoCache = Join-Path $OutputRoot 'gocache'
$benchGoTmp = Join-Path $OutputRoot 'gotmp'
New-Item -ItemType Directory -Force -Path $benchGoCache, $benchGoTmp | Out-Null

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

function Get-Median {
    param([Parameter(Mandatory)][double[]]$Values)
    $sorted = @($Values | Sort-Object)
    $count = $sorted.Count
    if ($count -eq 0) { return [double]::NaN }
    if ($count % 2 -eq 1) { return [double]$sorted[[int](($count - 1) / 2)] }
    return ([double]$sorted[$count / 2 - 1] + [double]$sorted[$count / 2]) / 2
}

# The measurement environment is pinned rather than inherited: this machine
# defaults to GOAMD64=v3 and GOEXPERIMENT=arenas, neither of which matches the
# baseline ASM_PLAN.md records.
$pinned = [ordered]@{
    GOAMD64      = 'v1'
    GOEXPERIMENT = 'none'
    CGO_ENABLED  = '0'
    GOFLAGS      = ''
    GOOS         = ''
    GOARCH       = ''
    GOCACHE      = $benchGoCache
    GOTMPDIR     = $benchGoTmp
}
$saved = @{}
foreach ($key in $pinned.Keys) {
    $saved[$key] = [System.Environment]::GetEnvironmentVariable($key)
}
$savedCorpus = $env:ZUCCHINI_BENCH_CORPUS
$savedInclude = $env:ZUCCHINI_BENCH_INCLUDE
$savedProbe = $env:ZUCCHINI_CORPUS_PROBE

try {
    foreach ($key in $pinned.Keys) {
        if ([string]::IsNullOrEmpty($pinned[$key])) {
            Remove-Item ('env:{0}' -f $key) -ErrorAction SilentlyContinue
        } else {
            Set-Item ('env:{0}' -f $key) $pinned[$key]
        }
    }
    $env:ZUCCHINI_BENCH_CORPUS = (Resolve-Path -LiteralPath $CorpusRoot).Path
    $env:ZUCCHINI_BENCH_INCLUDE = $Include

    $selectedPairs = @(
        Get-ChildItem -LiteralPath $env:ZUCCHINI_BENCH_CORPUS -Directory |
            Where-Object {
                $_.Name -match $Include -and
                (Test-Path -LiteralPath (Join-Path $_.FullName 'old.bin') -PathType Leaf) -and
                (Test-Path -LiteralPath (Join-Path $_.FullName 'new.bin') -PathType Leaf)
            } |
            Sort-Object Name |
            ForEach-Object { $_.Name }
    )
    if ($selectedPairs.Count -eq 0) {
        throw ('no corpus pairs under {0} match {1}' -f $env:ZUCCHINI_BENCH_CORPUS, $Include)
    }

    $goVersion = (& go version) -join ''
    $cpuName = 'unknown'
    try {
        $cpuName = (Get-ItemProperty -LiteralPath 'HKLM:\HARDWARE\DESCRIPTION\System\CentralProcessor\0' `
            -Name ProcessorNameString -ErrorAction Stop).ProcessorNameString.Trim()
    } catch {
        try {
            $cpuName = (Get-CimInstance -ClassName Win32_Processor | Select-Object -First 1 -ExpandProperty Name).Trim()
        } catch {
            Write-Warning ('could not read CPU model: {0}' -f $_.Exception.Message)
        }
    }

    $candidateTags = 'zucchini_asmcorpus'
    if ($Tags) { $candidateTags += ",$Tags" }
    $configs = @(
        [ordered]@{ Name = 'baseline';  Tags = 'zucchini_asmcorpus';         Binary = $null }
        [ordered]@{ Name = 'candidate'; Tags = $candidateTags; Binary = $null }
    )

    if ($BaselineBinary) {
        if (-not (Test-Path -LiteralPath $BaselineBinary -PathType Leaf)) {
            throw ('baseline test binary not found at {0}' -f $BaselineBinary)
        }
        $configs[0].Binary = (Resolve-Path -LiteralPath $BaselineBinary).Path
    }

    foreach ($config in $configs) {
        if ($config.Binary) {
            Write-Host ('using prebuilt {0}: {1}' -f $config.Name, $config.Binary)
            continue
        }
        $binary = Join-Path $OutputRoot ('{0}.test.exe' -f $config.Name)
        $config.Binary = $binary
        $buildArgs = @('test', '-c', '-o', $binary)
        if ($config.Tags) { $buildArgs += @('-tags', $config.Tags) }
        $buildArgs += '.'
        Write-Host ('compiling {0}{1} ...' -f $config.Name, ($(if ($config.Tags) { " (-tags $($config.Tags))" } else { '' })))
        Invoke-Tool -Path 'go' -Arguments $buildArgs
    }

    # Run the correctness/heap probe once per configuration before timing.
    # Besides recording patch hashes and peak heap, this applies every patch
    # and fails immediately if the reconstructed target differs.
    $probeByConfig = @{}
    $env:ZUCCHINI_CORPUS_PROBE = '1'
    foreach ($config in $configs) {
        $probeLog = Join-Path $OutputRoot ('{0}-probe.txt' -f $config.Name)
        Write-Host ('probing {0} correctness and peak heap ...' -f $config.Name)
        $probeOutput = & $config.Binary '-test.run=^TestZZCorpusProbe$' '-test.v' '-test.timeout=2h' 2>&1
        $probeExit = $LASTEXITCODE
        $probeOutput | Set-Content -LiteralPath $probeLog -Encoding UTF8
        if ($probeExit -ne 0) {
            throw ('{0} corpus probe failed with exit code {1}; see {2}' -f $config.Name, $probeExit, $probeLog)
        }
        $probeByConfig[$config.Name] = @($probeOutput | Where-Object { [string]$_ -match 'CORPUS name=' })
    }
    Remove-Item 'env:ZUCCHINI_CORPUS_PROBE' -ErrorAction SilentlyContinue

    # samples[config][pair] accumulates one entry per interleaved sample.
    $samplesByConfig = @{}
    foreach ($config in $configs) { $samplesByConfig[$config.Name] = @{} }

    $benchPattern = '^Benchmark(?<bench>\S+?)(?:-\d+)?\s+(?<n>\d+)\s+(?<ns>[0-9.]+)\s+ns/op(?:\s+(?<bytes>\d+)\s+B/op)?(?:\s+(?<allocs>\d+)\s+allocs/op)?'

    $runArgs = @(
        '-test.run=^$'
        '-test.bench=^BenchmarkGenerateCorpus$'
        '-test.benchtime=1x'
        '-test.benchmem'
        '-test.count=1'
        '-test.timeout=2h'
    )
    for ($sample = 1; $sample -le $Samples; $sample++) {
        $sampleLogs = @{}
        foreach ($config in $configs) { $sampleLogs[$config.Name] = @() }
        $orderedConfigs = if ($sample % 2 -eq 1) {
            @($configs[0], $configs[1])
        } else {
            @($configs[1], $configs[0])
        }

        foreach ($pairName in $selectedPairs) {
            $env:ZUCCHINI_BENCH_INCLUDE = ('^{0}$' -f [regex]::Escape($pairName))
            foreach ($config in $orderedConfigs) {
                $logPath = Join-Path $OutputRoot ('{0}-sample{1:d2}.txt' -f $config.Name, $sample)
                Write-Host ('sample {0}/{1}: {2} / {3}' -f $sample, $Samples, $pairName, $config.Name)

                $output = & $config.Binary @runArgs 2>&1
                $exitCode = $LASTEXITCODE
                $sampleLogs[$config.Name] += @($output)
                if ($exitCode -ne 0) {
                    $sampleLogs[$config.Name] | Set-Content -LiteralPath $logPath -Encoding UTF8
                    throw ('{0} sample {1} for {2} failed with exit code {3}; see {4}' -f `
                        $config.Name, $sample, $pairName, $exitCode, $logPath)
                }

                foreach ($line in $output) {
                    $match = [regex]::Match([string]$line, $benchPattern)
                    if (-not $match.Success) { continue }

                    # Sub-benchmark names arrive as GenerateCorpus/<pair>.
                    $benchName = $match.Groups['bench'].Value
                    $pair = ($benchName -split '/', 2)[-1]
                    if ($pair -ne $pairName) { continue }

                    $store = $samplesByConfig[$config.Name]
                    if (-not $store.Contains($pair)) { $store[$pair] = @() }
                    $store[$pair] += [ordered]@{
                        sample = $sample
                        nsOp   = [double]$match.Groups['ns'].Value
                        bytes  = if ($match.Groups['bytes'].Success) { [long]$match.Groups['bytes'].Value } else { $null }
                        allocs = if ($match.Groups['allocs'].Success) { [long]$match.Groups['allocs'].Value } else { $null }
                    }
                }
            }
        }

        foreach ($config in $configs) {
            $logPath = Join-Path $OutputRoot ('{0}-sample{1:d2}.txt' -f $config.Name, $sample)
            $sampleLogs[$config.Name] | Set-Content -LiteralPath $logPath -Encoding UTF8
        }
    }
    $env:ZUCCHINI_BENCH_INCLUDE = $Include

    $pairs = @($samplesByConfig['baseline'].Keys | Sort-Object)
    if ($pairs.Count -eq 0) {
        throw 'no benchmark results were parsed; inspect the sample logs under ' + $OutputRoot
    }

    # Profiles are intentionally taken after timing so profiler overhead and
    # cache state cannot affect the interleaved release-gate samples.
    $profilePaths = @{}
    if (-not $SkipCpuProfiles) {
        $profileRoot = Join-Path $OutputRoot 'profiles'
        New-Item -ItemType Directory -Force -Path $profileRoot | Out-Null
        foreach ($pair in $pairs) {
            $env:ZUCCHINI_BENCH_INCLUDE = ('^{0}$' -f [regex]::Escape($pair))
            $profilePath = Join-Path $profileRoot ('baseline-{0}.pprof' -f $pair)
            $profileLog = Join-Path $profileRoot ('baseline-{0}.txt' -f $pair)
            Write-Host ('profiling baseline: {0}' -f $pair)
            $profileOutput = & $configs[0].Binary @(
                '-test.run=^$'
                '-test.bench=^BenchmarkGenerateCorpus$'
                '-test.benchtime=1x'
                ('-test.cpuprofile={0}' -f $profilePath)
                '-test.timeout=2h'
            ) 2>&1
            $profileExit = $LASTEXITCODE
            $profileOutput | Set-Content -LiteralPath $profileLog -Encoding UTF8
            if ($profileExit -ne 0) {
                throw ('CPU profile for {0} failed with exit code {1}; see {2}' -f $pair, $profileExit, $profileLog)
            }
            $profilePaths[$pair] = $profilePath
        }
        $env:ZUCCHINI_BENCH_INCLUDE = $Include
    }

    # Extract the fields that must be identical. Keeping the original probe
    # lines in JSON also preserves peak heap and provenance without a fragile
    # second parser for every informational field.
    $probePattern = 'CORPUS name=(?<name>\S+).*?patch=(?<patch>\d+).*?patchSHA256=(?<patchHash>[0-9a-f]+).*?newSHA256=(?<newHash>[0-9a-f]+)'
    $probeSummary = @{}
    foreach ($config in $configs) {
        $probeSummary[$config.Name] = @{}
        foreach ($line in $probeByConfig[$config.Name]) {
            $match = [regex]::Match([string]$line, $probePattern)
            if (-not $match.Success) { continue }
            $probeSummary[$config.Name][$match.Groups['name'].Value] = [ordered]@{
                patchBytes = [long]$match.Groups['patch'].Value
                patchSHA256 = $match.Groups['patchHash'].Value
                newSHA256 = $match.Groups['newHash'].Value
            }
        }
    }
    foreach ($pair in $pairs) {
        if (-not $probeSummary['baseline'].Contains($pair) -or -not $probeSummary['candidate'].Contains($pair)) {
            throw ('missing parsed probe result for {0}' -f $pair)
        }
        $baseProbe = $probeSummary['baseline'][$pair]
        $candProbe = $probeSummary['candidate'][$pair]
        if ($baseProbe.patchBytes -ne $candProbe.patchBytes -or
            $baseProbe.patchSHA256 -ne $candProbe.patchSHA256 -or
            $baseProbe.newSHA256 -ne $candProbe.newSHA256) {
            throw ('baseline/candidate patch mismatch for {0}; inspect probe logs under {1}' -f $pair, $OutputRoot)
        }
    }

    $rows = @()
    foreach ($pair in $pairs) {
        $baseSamples = @($samplesByConfig['baseline'][$pair])
        if (-not $samplesByConfig['candidate'].Contains($pair)) {
            Write-Warning ('{0}: candidate produced no samples; skipping' -f $pair)
            continue
        }
        $candSamples = @($samplesByConfig['candidate'][$pair])

        $baseMedianNs = Get-Median -Values ([double[]]($baseSamples | ForEach-Object { $_.nsOp }))
        $candMedianNs = Get-Median -Values ([double[]]($candSamples | ForEach-Object { $_.nsOp }))
        $baseBytes = ($baseSamples | ForEach-Object { $_.bytes } | Where-Object { $null -ne $_ } | Select-Object -First 1)
        $candBytes = ($candSamples | ForEach-Object { $_.bytes } | Where-Object { $null -ne $_ } | Select-Object -First 1)

        # Positive percent means the candidate is faster.
        $deltaPct = if ($baseMedianNs -gt 0) { (($baseMedianNs - $candMedianNs) / $baseMedianNs) * 100 } else { [double]::NaN }
        $pairedDeltas = for ($i = 0; $i -lt [math]::Min($baseSamples.Count, $candSamples.Count); $i++) {
            if ($baseSamples[$i].nsOp -gt 0) {
                (($baseSamples[$i].nsOp - $candSamples[$i].nsOp) / $baseSamples[$i].nsOp) * 100
            }
        }
        $pairedMedianDeltaPct = Get-Median -Values ([double[]]$pairedDeltas)

        $rows += [ordered]@{
            pair              = $pair
            baselineSamples   = $baseSamples.Count
            candidateSamples  = $candSamples.Count
            baselineMedianMs  = [math]::Round($baseMedianNs / 1e6, 1)
            candidateMedianMs = [math]::Round($candMedianNs / 1e6, 1)
            deltaPercent      = [math]::Round($deltaPct, 2)
            pairedMedianDeltaPercent = [math]::Round($pairedMedianDeltaPct, 2)
            baselineMinMs     = [math]::Round((($baseSamples | ForEach-Object { $_.nsOp } | Measure-Object -Minimum).Minimum) / 1e6, 1)
            candidateMinMs    = [math]::Round((($candSamples | ForEach-Object { $_.nsOp } | Measure-Object -Minimum).Minimum) / 1e6, 1)
            baselineBytesOp   = $baseBytes
            candidateBytesOp  = $candBytes
        }
    }

    Write-Host ''
    $rows | ForEach-Object { [pscustomobject]$_ } |
        Format-Table -Property pair, baselineMedianMs, candidateMedianMs, deltaPercent, pairedMedianDeltaPercent, baselineBytesOp, candidateBytesOp -AutoSize |
        Out-String -Width 240 | Write-Host

    $result = [ordered]@{
        generatedUtc = (Get-Date).ToUniversalTime().ToString('o')
        goVersion    = $goVersion
        cpu          = $cpuName
        os           = [Environment]::OSVersion.VersionString
        goamd64      = $pinned.GOAMD64
        goexperiment = $pinned.GOEXPERIMENT
        candidateTags = $Tags
        samples      = $Samples
        corpusRoot   = $env:ZUCCHINI_BENCH_CORPUS
        summary      = $rows
        raw          = $samplesByConfig
        probes       = $probeSummary
        probeLines   = $probeByConfig
        cpuProfiles  = $profilePaths
    }
    $resultPath = Join-Path $OutputRoot 'asm-bench.json'
    $result | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $resultPath -Encoding UTF8

    $candidateLabel = if ($Tags) { $Tags } else { 'candidate' }
    Write-Host ('positive deltaPercent means {0} is faster than baseline.' -f $candidateLabel)
    Write-Host ('result written to {0}' -f $resultPath)
} finally {
    foreach ($key in $saved.Keys) {
        if ($null -eq $saved[$key]) {
            Remove-Item ('env:{0}' -f $key) -ErrorAction SilentlyContinue
        } else {
            Set-Item ('env:{0}' -f $key) $saved[$key]
        }
    }
    if ($null -eq $savedCorpus) {
        Remove-Item 'env:ZUCCHINI_BENCH_CORPUS' -ErrorAction SilentlyContinue
    } else {
        $env:ZUCCHINI_BENCH_CORPUS = $savedCorpus
    }
    if ($null -eq $savedInclude) {
        Remove-Item 'env:ZUCCHINI_BENCH_INCLUDE' -ErrorAction SilentlyContinue
    } else {
        $env:ZUCCHINI_BENCH_INCLUDE = $savedInclude
    }
    if ($null -eq $savedProbe) {
        Remove-Item 'env:ZUCCHINI_CORPUS_PROBE' -ErrorAction SilentlyContinue
    } else {
        $env:ZUCCHINI_CORPUS_PROBE = $savedProbe
    }
}
