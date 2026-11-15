# Baut die Release-Binaries des Wurm-Stacks unter Windows.
#
# Das Gegenstueck zu build.sh: gleicher Aufruf, gleiches Ergebnis, auf einer
# Windows-Maschine. Die Rustflags gelten auch hier nur fuer die erzeugten
# Binaries.
#
# Aufruf:
#   kx\scripts\build.ps1 [zielverzeichnis]

$ErrorActionPreference = "Stop"

Push-Location (Join-Path $PSScriptRoot "..")

$ziel = if ($args.Count -ge 1) { $args[0] } else { "dist" }
New-Item -ItemType Directory -Force -Path $ziel | Out-Null

$env:RUSTFLAGS = "$($env:RUSTFLAGS) -C strip=symbols"

Write-Host "== Release-Build =="
cargo build --release -p kx-server -p kx-agent -p kx-cli

foreach ($bin in @("kx-server.exe", "kx-agent.exe", "kx-cli.exe")) {
    Copy-Item "target\release\$bin" $ziel -Force
}

Write-Host "== fertig in $ziel =="
Get-ChildItem $ziel | Format-Table Name, Length

Pop-Location
