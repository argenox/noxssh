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

Write-Host "Building noxssh ($Config)..."
cmake --build $BuildDir --config $Config

Write-Host "Build complete. Binaries are in: $BinDir"
