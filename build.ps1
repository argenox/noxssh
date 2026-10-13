param(
    [ValidateSet("Debug", "Release")]
    [string]$Config = "Release"
)

$ErrorActionPreference = "Stop"

$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
$BuildDir = Join-Path $Root "build"
$BinDir = Join-Path $Root "bin"

if (-not (Test-Path $BinDir)) {
    New-Item -ItemType Directory -Path $BinDir | Out-Null
}

Write-Host "Configuring CMake project..."
cmake -S $Root -B $BuildDir -DCMAKE_BUILD_TYPE=$Config

Write-Host "Building noxssh (client) and noxsshd (server), $Config..."
cmake --build $BuildDir --config $Config

$client = Join-Path $BinDir "noxssh.exe"
$daemon = Join-Path $BinDir "noxsshd.exe"
if (-not (Test-Path $client)) {
    Write-Warning "Expected client binary: $client"
}
if (-not (Test-Path $daemon)) {
    Write-Warning "Expected server binary: $daemon"
}
Write-Host "Build complete. Binaries are in: $BinDir"
