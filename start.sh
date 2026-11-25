#!/usr/bin/env bash
# Testwurm · EIN Befehl für die Präsentation.
# Prüft Abhängigkeiten, baut einmalig (falls nötig), startet Labor + GUI und
# öffnet den Browser. Danach: nur noch klicken.
set -euo pipefail
cd "$(dirname "$0")"

echo "== Testwurm · Präsentationsstart =="

# 1. Werkzeuge prüfen
if ! command -v node >/dev/null 2>&1; then
  echo "FEHLER: Node.js (>=18) fehlt. Bitte installieren: https://nodejs.org" >&2
  exit 1
fi
NODE_MAJOR="$(node -p 'process.versions.node.split(".")[0]')"
if [ "$NODE_MAJOR" -lt 18 ]; then
  echo "FEHLER: Node.js >= 18 nötig (gefunden: $(node --version))." >&2
  exit 1
fi
if ! command -v docker >/dev/null 2>&1; then
  echo "FEHLER: Docker fehlt. Bitte Docker Desktop / Docker Engine installieren." >&2
  exit 1
fi

# Das Labor braucht Linux-Binaries: C2 und Agent laufen als Linux-Container.
# Ein nativer macOS-Build würde im Container nicht starten (Exec format error).
HOST_OS="$(uname -s)"
if [ "$HOST_OS" != "Linux" ]; then
  echo "FEHLER: Das Labor braucht Linux-Binaries (Container). Dieser Host ist $HOST_OS." >&2
  echo "Bitte auf einem Linux-Host starten – oder die Binaries dort bauen und kx/dist/ mitbringen." >&2
  exit 1
fi

# 2. Release-Binaries (einmaliger Build, danach sofort startklar)
if [ ! -x kx/dist/kx-server ] || [ ! -x kx/dist/kx-agent ]; then
  export PATH="$HOME/.cargo/bin:$PATH"
  if ! command -v cargo >/dev/null 2>&1; then
    echo "FEHLER: cargo fehlt für den einmaligen Rust-Build. Bitte Rust installieren: https://rustup.rs" >&2
    exit 1
  fi
  echo "== Release-Build läuft (einmalig, einige Minuten) =="
  bash kx/scripts/build.sh
fi

# 3. Server-Schlüssel für die Versiegelung der Beute (einmalig)
if [ ! -f lab/run/server-pub.json ]; then
  export PATH="$HOME/.cargo/bin:$PATH"
  echo "== Server-Schlüssel erzeugen =="
  mkdir -p lab/run
  (cd kx && cargo run --release -p kx-core --example gen_server_key -- \
    hybrid ../lab/run/server-key.json ../lab/run/server-pub.json)
  chmod 600 lab/run/server-key.json
fi

# 4. Architektur-Graph aktualisieren (schnell, immer)
node scripts/review-graph.mjs

# 5. GUI + Labor starten (öffnet den Browser)
exec node orchestrator/server.mjs