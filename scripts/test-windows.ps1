#Requires -Version 5.1
[CmdletBinding()]
param(
    [string]$Tags = ''
)

$ErrorActionPreference = 'Stop'
$repoRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$saved = @{}
foreach ($name in 'CGO_ENABLED', 'GOAMD64', 'GOEXPERIMENT', 'GOFLAGS', 'GOCACHE', 'GOMODCACHE', 'GOTMPDIR') {
    $saved[$name] = [System.Environment]::GetEnvironmentVariable($name, 'Process')
}

try {
    $env:CGO_ENABLED = '0'
    $env:GOAMD64 = 'v1'
    $env:GOEXPERIMENT = 'none'
    $env:GOCACHE = Join-Path $repoRoot '.gocache'
    $env:GOMODCACHE = Join-Path $repoRoot '.gomodcache'
    $env:GOTMPDIR = Join-Path $repoRoot '.gotmp\test'
    New-Item -ItemType Directory -Force -Path $env:GOCACHE, $env:GOMODCACHE, $env:GOTMPDIR | Out-Null
    Remove-Item Env:GOFLAGS -ErrorAction SilentlyContinue

    $goArgs = @('test', '-p=1', '-count=1')
    if ($Tags) {
        $goArgs += @('-tags', $Tags)
    }
    $goArgs += './...'

    Push-Location $repoRoot
    try {
        & go @goArgs
        if ($LASTEXITCODE -ne 0) {
            throw "go test failed with exit code $LASTEXITCODE"
        }
    } finally {
        Pop-Location
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
