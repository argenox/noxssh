# Smoke: noxsshd + noxssh to localhost (Windows).
$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
$Noxssh = Join-Path $Root "bin/noxssh.exe"
$Noxsshd = Join-Path $Root "bin/noxsshd.exe"
if (-not (Test-Path $Noxssh) -or -not (Test-Path $Noxsshd)) {
  Write-Error "Missing $Noxssh or $Noxsshd"
}
$keyPath = Join-Path $env:TEMP ("noxsshd-smoke-" + [Guid]::NewGuid().ToString() + ".key")
$rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
$bytes = New-Object byte[] 32
$rng.GetBytes($bytes)
[IO.File]::WriteAllBytes($keyPath, $bytes)
$port = if ($env:NOXSSH_SMOKE_PORT) { [int]$env:NOXSSH_SMOKE_PORT } else { 4022 }
$args = @("-p", "$port", "--password", "smoketest", "--host-key", $keyPath)
$proc = Start-Process -FilePath $Noxsshd -ArgumentList $args -PassThru -WindowStyle Hidden
Start-Sleep -Seconds 2
try {
  $out = & $Noxssh -p $port -w smoketest user@127.0.0.1 "echo ci_ok" 2>&1 | Out-String
  if ($out -notmatch "ci_ok") {
    Write-Error "Expected ci_ok in output: $out"
  }
  Write-Host "ci_smoke_sshd: ok"
}
finally {
  Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
  Remove-Item -Force $keyPath -ErrorAction SilentlyContinue
}
