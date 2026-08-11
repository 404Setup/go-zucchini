param(
    [string]$Output = "dist\zucchini.exe",
    [string]$GoAmd64 = 'v1',
    [string]$GoExperiment = 'none',
    [switch]$Hardened
)

$ErrorActionPreference = 'Stop'
$repoRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$outputPath = [System.IO.Path]::GetFullPath((Join-Path $repoRoot $Output))
$outputDir = [System.IO.Path]::GetDirectoryName($outputPath)
New-Item -ItemType Directory -Force -Path $outputDir | Out-Null

$saved = @{}
foreach ($name in 'CGO_ENABLED', 'GOAMD64', 'GOEXPERIMENT', 'GOFLAGS', 'GOCACHE', 'GOMODCACHE', 'GOTMPDIR') {
    $saved[$name] = [System.Environment]::GetEnvironmentVariable($name, 'Process')
}

try {
    $env:CGO_ENABLED = '0'
    $env:GOAMD64 = $GoAmd64
    $env:GOEXPERIMENT = $GoExperiment
    $env:GOCACHE = Join-Path $repoRoot '.gocache'
    $env:GOMODCACHE = Join-Path $repoRoot '.gomodcache'
    $env:GOTMPDIR = Join-Path $repoRoot '.gotmp\release'
    New-Item -ItemType Directory -Force -Path $env:GOCACHE, $env:GOMODCACHE, $env:GOTMPDIR | Out-Null
    Remove-Item Env:GOFLAGS -ErrorAction SilentlyContinue

    $goArgs = @('build', '-buildvcs=true')
    if ($Hardened) {
        $goArgs += @('-trimpath', '-buildmode=pie')
    }
    $goArgs += @('-o', $outputPath, './cmd/zucchini')

    & go @goArgs
    if ($LASTEXITCODE -ne 0) {
        throw "go build failed with exit code $LASTEXITCODE"
    }
} finally {
    foreach ($name in $saved.Keys) {
        $value = $saved[$name]
        if ($null -eq $value) {
            Remove-Item "Env:$name" -ErrorAction SilentlyContinue
        } else {
            [System.Environment]::SetEnvironmentVariable($name, $value, 'Process')
        }
    }
}

$hash = (Get-FileHash -LiteralPath $outputPath -Algorithm SHA256).Hash.ToLowerInvariant()
$hashLine = "$hash  $([System.IO.Path]::GetFileName($outputPath))"
[System.IO.File]::WriteAllText("$outputPath.sha256", "$hashLine`n")
Write-Host $hashLine
