#!/bin/sh
# Patient0-Entrypoint: startet den gemounteten Agenten mit den übergebenen Args.
# Binary, Assets, Zertifikat und Server-Schlüssel kommen als Read-only-Mounts
# vom Orchestrator (/opt/kx/...).
set -e
# Cron-Daemon starten: ohne systemd im Container ist der @reboot-Cron-Job
# der Persistenz-Weg des Agenten. Ein frisch gestarteter Container hat eine
# leere Crontab — der Daemon startet hier also nichts Fremdes.
/usr/sbin/cron
exec /opt/kx/kx-agent "$@"
