# Testwurm – Präsentations-Demo-Skript (60–90 Sekunden)

**Was hier läuft:** Kein Fake, keine Simulation. Ein echter kx-Netzwerkwurm
(Rust) läuft in einem isolierten Docker-Labor gegen zwei SSH-Zielcontainer mit
kontrollierten Credentials. Die GUI zeigt den echten Zustand des C2-Servers.

**Zielgruppe:** Präsentation ohne Terminal-Kenntnisse.
**Voraussetzung:** `./start.sh` wurde gestartet, Browser offen auf `http://127.0.0.1:8321`.

---

## 0–10s · Einstieg: GUI zeigen

**Klick:** Keiner – nur zeigen.

**Sprechtext:**
> „Willkommen bei Testwurm. Oben das Status-Banner zeigt ‚Bereit', links die
> Steuerung, in der Mitte den Live-Graphen des Wurms und rechts die
> Kontext-Kompression in Echtzeit. Dahinter läuft ein echtes C2-System in
> einem isolierten Labor-Netz – nichts davon berührt produktive Systeme."

---

## 10–35s · Happy Path starten

**Klick:** Szenariokarte **„Happy Path"** wählen, dann **„Start"**.

**Sprechtext (während der Wurm läuft):**
> „Der Agent startet im Labor-Container, meldet sich beim C2-Server, sammelt
> lokale Beute – Shadow-Datei, SSH-Key, AWS-Credentials, alles Wegwerf-Daten
> im Container. Dann scannt er das Netz und findet target1 mit
> Default-Credentials. Jeder Schritt wird live grün. Rechts sehen Sie die
> Kontext-Kompression: Statt des gesamten Logs bleiben nur Fakten-Summaries
> plus die letzten Zeilen – die Ersparnis ist echt gemessen."

**Beobachten:** Banner „Läuft" (blau), Knoten werden nacheinander grün,
Persistenz wird gelb (ehrlich: kein systemd im Container – der Fehler wird
abgefangen), savedPct steigt, Banner „Abgeschlossen".

---

## 35–60s · Fehler & Recovery

**Klick:** **„Reset Demo"**, Szenariokarte **„Fehler & Recovery"** wählen, **„Start"**.

**Sprechtext:**
> „Jetzt ein Ziel mit starkem Passwort. Der Scan findet den Host, aber der
> Zugriff scheitert – der Knoten wird gelb statt grün, und das ist korrekt
> so. Trotzdem arbeitet der Task-Kanal weiter: Ein Operator-Task wird vom
> Agenten geholt, ausgeführt und zurückgemeldet. Fehler werden abgefangen,
> das System bleibt bedienbar."

**Beobachten:** target2 gelb (warning, erkannt aber kein Zugriff), Task-Kanal
grün, Telemetrie zählt Fehler und Erholungen.

---

## 60–80s · Architektur-Tab

**Klick:** Tab **„Architektur"**.

**Sprechtext:**
> „Hier die echte Modulstruktur des Rust-Workspace: neun Crates, automatisch
> aus den Cargo-Manifesten extrahiert. Core blau, Server grün, Agent rot,
> CLI hellblau – die Pfeile sind die tatsächlichen Abhängigkeiten."

**Beobachten:** Gruppierter SVG-Graph (core/server/agent/cli) mit
Abhängigkeitspfeilen.

---

## 80–90s · Reset & Fazit

**Klick:** Tab **„Live-Labor"**, dann **„Reset Demo"**.

**Sprechtext:**
> „Reset – Container weg, Datenbank leer, Ziele frisch, alles wieder bei
> ‚Bereit'. Zusammengefasst: ein echtes, lauffähiges C2-System im isolierten
> Labor, eine idiotensichere Oberfläche, ehrliche Fehlerbehandlung und
> gemessene Kontext-Ersparnis. Vielen Dank!"

---

## Tastatur-Shortcuts

| Taste | Aktion |
|-------|--------|
| `Leertaste` | Start / Pause |
| `S` | Einzelschritt |
| `R` | Reset Demo |

---

## Hinweise

- **Pause ist echt:** Der Container wird per cgroup-Freezer eingefroren.
  **Einzelschritt** lässt ihn 700 ms laufen und friert ihn wieder ein.
- **Kein Terminal nötig** während der Präsentation – alles im Browser.
- **Fehlerbanner** erscheint automatisch bei Verbindungsverlust; die GUI
  bleibt bedienbar und pollt weiter.
- **Log-Details:** Klick auf einen Eintrag klappt die Rohzeile auf.
- **Sicherheit:** Agent nur im Container, Ziele nur im Docker-Netz
  `kx-lab` (172.31.99.0/24), alle Credentials sind Wegwerf-Laborwerte.