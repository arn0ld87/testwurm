#!/usr/bin/env bash
# Testwurm · lokale Qualitäts-Gates (dasselbe prüft die CI in demo.yml).
# Nutzung: bash scripts/check.sh [--with-rust]
#   ohne Flag: Node-Tests, Syntax, Shell-Gates, Graph-Frische (schnell)
#   --with-rust: zusätzlich cargo fmt --check + cargo test --workspace
set -euo pipefail
cd "$(dirname "$0")/.."

echo "== 1/5 Node-Unit-Tests =="
node --test orchestrator/*.test.mjs

echo "== 2/5 JS-Syntax =="
for f in orchestrator/*.mjs scripts/*.mjs public/app.js; do
  node --check "$f"
done

echo "== 3/5 Shell-Syntax + shellcheck (falls vorhanden) =="
for f in start.sh lab/*.sh; do
  bash -n "$f"
done
if command -v shellcheck >/dev/null 2>&1; then
  shellcheck --severity=warning start.sh lab/*.sh
else
  echo "(shellcheck nicht installiert – nur bash -n; die CI prüft mit shellcheck)"
fi

echo "== 4/5 Architektur-Graph frisch? =="
node scripts/review-graph.mjs
if ! git diff --quiet -- public/architecture.json; then
  echo "FEHLER: public/architecture.json ist veraltet. 'make graph' ausführen und committen." >&2
  exit 1
fi

if [ "${1:-}" = "--with-rust" ]; then
  echo "== 5/5 Rust: fmt + Workspace-Tests =="
  (cd kx && cargo fmt --check && cargo test --workspace)
else
  echo "== 5/5 Rust übersprungen (--with-rust für fmt + Tests) =="
fi

echo "CHECK_PASS"