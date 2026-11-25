#!/bin/sh
# Patient0-Entrypoint: startet den gemounteten Agenten mit den übergebenen Args.
# Binary, Assets, Zertifikat und Server-Schlüssel kommen als Read-only-Mounts
# vom Orchestrator (/opt/kx/...).
set -e
exec /opt/kx/kx-agent "$@"