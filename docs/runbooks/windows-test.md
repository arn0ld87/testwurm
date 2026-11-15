# Windows-Test: den Wurm in einer echten Windows-VM prüfen

Der Test beantwortet eine Frage: **registriert sich der Agent in einer echten
Windows-Umgebung beim C2, und kommt die Beute verschlüsselt an?**

Er ist ein Skript mit einem Urteil, keine Folge von Tastendrucken:

```bash
# Auf dem Host, auf dem die VM laeuft:
bash kx/scripts/kx-vm-test.sh 45
# ERGEBNIS: PASS — der Agent hat sich beim C2 registriert
```

**Fertig, wenn:** die Ausgabe `ERGEBNIS: PASS` zeigt. Bei `FAIL` holt das
Skript das Agent-Log aus der VM und gibt es aus — das Log ist der erste
Schritt der Diagnose, nicht das Letzte.

## Was der Test macht

| Schritt | Was |
|---|---|
| 1 | Die Adresse ermitteln, unter der die VM den Host erreicht |
| 2 | Prüfen, ob der C2 mit passendem TLS-Namen laeuft; sonst neu starten |
| 3 | Die Dateien (Agent, Schluessel, Public Key) in ein HTTP-Verzeichnis legen |
| 4 | Das Zertifikat holen — **nach** Schritt 3 |
| 5 | Den Befehl in der VM tippen und den Agenten starten |
| 6 | Warten, `GET /api/hosts` fragen, auf `172.17.0.2` pruefen |

## Voraussetzungen

- Ein Host mit KVM (`/dev/kvm`), Docker und `qemu-kvm` — der Test laeuft
  in einem Container (`dockurr/windows`) mit Windows Server 2022.
- Der C2 laeuft auf demselben Host, unter der Adresse aus Schritt 1. Der
  TLS-Name muss dazu passen: der Agent prueft das Zertifikat gegen die URL.
- Impacket auf dem Host, falls der Wurm ueber SMB Kommandos ausfuehren soll
  (nur fuer den Exploit-Pfad, nicht fuer den Registrierungsnachweis).

## Der Weg zum ersten Lauf

```bash
# 1. Das Image holen und die VM starten
sudo docker pull dockurr/windows
sudo docker run -d --name kx-win --device /dev/kvm \
  --security-opt label=disable \
  -e VERSION=2022 -e RAM_SIZE=4G -e CPU_CORES=2 -e DISK_SIZE=32G \
  -e USERNAME=kxadmin -e PASSWORD="..." \
  -p 3389:3389/tcp -v /srv/kx-win:/storage dockurr/windows

# 2. Den Agenten fuer Windows bauen
cargo build --release --target x86_64-pc-windows-gnu -p kx-agent
#   Der mingw-Compiler wird gebraucht: ring hat ein build.rs, das C uebersetzt.

# 3. Den C2 bauen und starten, das Schluesselpaar erzeugen
cd kx && cargo build --release -p kx-server
cargo run --release -p kx-core --example gen_server_key -- \
  hybrid /srv/kx-win/kx-server-key.json /srv/kx-win/kx-server-pub.json
./target/release/kx-server --host 0.0.0.0 --port 8443 --db /srv/kx-c2/kx.db \
  --token "$(cat /srv/kx-win/kx-token.txt)" --cn <DIE-ADRESSE>

# 4. Den Test fahren
bash kx/scripts/kx-vm-test.sh 45
```

## Stolperfallen

**Der C2 erzeugt bei jedem Start ein neues Zertifikat.** `rcgen` signiert
selbstsigniert und frisch. Liegt in dem HTTP-Verzeichnis noch das alte,
meldet der Agent `BadSignature`. Deshalb holt das Skript das Zertifikat
**nach** dem Kopieren der Dateien — in der anderen Reihenfolge gewinnt die
alte Kopie.

**`rsync -a` überträgt die Zeitstempel der Quelle.** Der Workspace liegt auf
einer anderen Zeitzone als der Host, und Cargo baut nur neu, was neuer
aussieht. Deshalb ohne Zeitstempel übertragen: `rsync -rz`.

**Der QEMU-Monitor nimmt nur eine Verbindung gleichzeitig.** Und `nc`
puffert die Zeilen, schickt sie erst am Ende. Zwei Fehler zusammen: Der
Tipp kommt fragmentiert an. `kx/scripts/kx-vm-control.sh` schickt darum
jede Taste ueber eine eigene Verbindung (`nc -q 0` schliesst sofort) und
wartet dazwischen.

**Die Zeichenuebersetzung braucht Ziffern.** Eine IP-Adresse besteht aus
Ziffern. Fehlt eine Zeichenklasse, bricht die Uebersetzung ab und der Rest
des Textes kommt nie an. `kx-vm-control.sh selbsttest` prueft das: die
Anzahl der Keycodes muss der Anzahl der Zeichen entsprechen.

**`sc.exe` und `schtasks` schreiben ihre Fehler nach stdout.** Wer nur
stderr liest, meldet einen Fehler ohne Text. Die Fehlermeldung des
Windows-Adapters liest deshalb beide Streams.

**Der Agent ist kein Windows-Dienst.** Er meldet sich beim Start nie beim
Service Control Manager, und der bricht nach 30 Sekunden mit `FAILED 1053`
ab. Die Persistenz laeuft ueber den Run-Key, nicht ueber `sc.exe`.

**Ohne ARP gibt es keine Entdeckung — aber einen Abbruch.** Der ARP-Sweep
braucht AF_PACKET und gibt es nur unter Linux. Unter Windows klopft der
Agent den Bereich aus `--start … --end` ab; der TCP-Scan entscheidet, wer
antwortet.

## Wenn der Test rot ist

1. **Das Agent-Log lesen.** Das Skript holt es nach einem Fehlschlag aus
   der VM. Es nennt den Grund als letzte Zeile.
2. **Den C2 pruefen.** `curl -sk -H "Authorization: Bearer $(cat
   /srv/kx-win/kx-token.txt)" https://127.0.0.1:8443/api/hosts` — leer heisst:
   der Agent kam nicht durch.
3. **Die VM ansehen.** `kx/scripts/kx-vm-control.sh shot /tmp/s.ppm` macht
   einen Bildschirmabzug ueber den QEMU-Monitor; im Container liegt er unter
   `/tmp/s.ppm`.
4. **Den Test enger ziehen.** `kx-vm-control.sh text "echo TEST"` in der VM
   tippt und zeigt, ob der Weg in die VM ueberhaupt funktioniert.
