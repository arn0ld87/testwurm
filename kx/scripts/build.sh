#!/bin/bash
# Baut die Release-Binaries des Wurm-Stacks.
#
# Die Cargo-Aliase in .cargo/config.toml decken den Alltagsfall ab. Dieses
# Skript ist der eine Aufruf, den CI und der Betrieb benutzen: er baut alle
# vier Binaries, legt sie in einem Verzeichnis zusammen und setzt die
# Rustflags, die nur fuer die erzeugten Binaries gelten sollen.
#
# Aufruf:
#   kx/scripts/build.sh [zielverzeichnis]
#
# Ergebnis: <ziel>/kx-server, <ziel>/kx-agent, <ziel>/kx-cli
#           (kx-agent.exe bzw. .exe auf Windows)

set -euo pipefail

cd "$(dirname "$0")/.."

ZIEL="${1:-dist}"
mkdir -p "$ZIEL"

export RUSTFLAGS="${RUSTFLAGS:-} -C strip=symbols"

echo "== Release-Build =="
cargo build --release -p kx-server -p kx-agent -p kx-cli

for bin in kx-server kx-agent kx-cli; do
    # Atomarer Austausch: ein laufender Container kann das Binary gemountet
    # halten ("Text file busy"); rename ersetzt den Verzeichniseintrag, der
    # laufende Prozess behält seinen alten Inode.
    cp "target/release/$bin" "$ZIEL/.$bin.tmp"
    mv -f "$ZIEL/.$bin.tmp" "$ZIEL/$bin"
done

echo "== fertig in $ZIEL =="
ls -la "$ZIEL"
