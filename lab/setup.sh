#!/usr/bin/env bash
# Labor-Setup: isoliertes Docker-Netz + zwei Images. Idempotent.
# Berührt keine bestehenden Container/Netze anderer Projekte.
set -euo pipefail
cd "$(dirname "$0")/.."

NET=kx-lab
SUBNET=172.31.99.0/24

if ! command -v docker >/dev/null 2>&1; then
  echo "FEHLER: docker fehlt. Bitte Docker installieren." >&2
  exit 1
fi

if ! docker network inspect "$NET" >/dev/null 2>&1; then
  echo "== Labor-Netz $NET ($SUBNET) =="
  docker network create "$NET" --subnet "$SUBNET" --internal >/dev/null
fi

echo "== Labor-Images bauen =="
docker build -q -t kx-lab-target -f lab/Dockerfile.target lab/ >/dev/null
docker build -q -t kx-lab-patient0 -f lab/Dockerfile.patient0 lab/ >/dev/null

echo "Labor bereit: Netz $NET, Images kx-lab-target + kx-lab-patient0."