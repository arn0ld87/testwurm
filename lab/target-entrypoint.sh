#!/bin/sh
# Labor-Ziel-Entrypoint: setzt das Root-Passwort aus ROOT_PW und startet sshd.
# ROOT_PW wird vom Orchestrator pro Szenario vergeben (Default-Credential vs. starkes Passwort).
set -e
echo "root:${ROOT_PW:?ROOT_PW fehlt}" | chpasswd
sed -i 's/^#\?PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config
sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config
exec /usr/sbin/sshd -D -e