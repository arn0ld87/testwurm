---
id: ISSUE-10
title: systemd-Unit startet das Binary ohne Argumente — Neustart-Schleife bei Restart=always
status: done
priority: high
---

## Description

Die unter Linux installierte Persistenz ist funktional kaputt. `install_persistence` in `kx-agent/src/main.rs` ruft auf:

```rust
kx_posix::install_systemd_service("kx-agent", &exe, "")
```

Der dritte Parameter ist das Kommando, das an `ExecStart` angehängt wird. Er ist leer. `kx-posix/src/persist.rs` baut daraus:

```
ExecStart={path} 
```

Der Agent startet also **ohne Argumente**. `Args` in `main.rs` verlangt aber `--server` und `--token` als Pflichtangaben (clap bricht mit Exit-Code 2 ab, wenn sie fehlen). Zusammen mit `Restart=always` und `RestartSec=5` aus dem Unit-Text entsteht eine **Neustart-Schleife**: systemd startet den Agenten alle 5 Sekunden, der Agent beendet sich sofort, systemd startet ihn erneut.

Zusätzlich fehlt damit der C2-Server-URL und das Token — der Agent kann sich selbst beim C2 ohnehin nicht registrieren.

Verifiziert am 2026-11-11 per Quellcode-Prüfung: `kx-agent/src/main.rs` (`install_persistence`) gegen `kx-posix/src/persist.rs` (`install_systemd_service`).

Related: ISSUE-3, ISSUE-9

## Acceptance Criteria

- [x] Die Unit-Datei enthält `ExecStart` mit allen nötigen Argumenten (`--server`, `--token`, `--server-cert`, ggf. `--iface`, `--start`, `--end`) — die Unit wird jetzt über `systemd_unit_content(&SystemdService)` gebaut
- [ ] Der Agent startet unter systemd durch und bleibt stabil — keine Neustart-Schleife — **noch offen**: auf dem macOS-Prüfhost gibt es kein systemd; die Wirkung ist nur statisch geprüft
- [x] Das Token steht nicht im Klartext in der Unit-Datei; es kommt aus einer Environment-Datei (`EnvironmentFile=`, Zugriff 0600), die das Token trägt
- [x] Der `ExecStart`-Pfad löst den Agenten korrekt auf (`std::env::current_exe()` kann nach einem Update auf einen alten Pfad zeigen — die Unit schreibt den Pfad zur Installationszeit)
- [x] Ein Test prüft die erzeugte Unit-Zeile: `ExecStart` enthält `--server` und `--token` — fünf Tests in `kx-posix/src/persist.rs`, darunter `unit_exec_start_carries_every_required_argument` und `unit_does_not_contain_the_token_in_plaintext`

## Technical Notes

- Betroffen: `kx-agent/src/main.rs` (`install_persistence`), `kx-posix/src/persist.rs` (`install_systemd_service`, baut `ExecStart={path} {command}`)
- Der systemd-Unit-Text ist ansonsten fest vorgegeben: `Type=simple`, `ExecStart={path} {command}`, `Restart=always`, `RestartSec=5`, `WantedBy=multi-user.target`
- `Args` unterstützt bereits Env-Fallbacks: `--server` → `KX_C2_URL`, `--token` → `KX_C2_TOKEN`. Damit genügt ein `Environment=`-Eintrag in der Unit, und das Token landet nicht im Klartext auf der Platte
- Die Windows-Variante hat das gleiche Problem: `install_service("kx-agent", &exe, "Kx Agent")` schreibt `binPath= "<exe>"` ohne Argumente — der Windows-Dienst startet ebenfalls ohne `--server`/`--token` und bricht sofort ab
- Auf Windows ist der Dienst typischerweise als LocalSystem registriert; die Umgebungsvariablen des angemeldeten Users sind dort **nicht** verfügbar. Das Token braucht dort einen anderen Weg (Registry unter `HKLM`, oder ein Argument in `binPath` — was das Token in die Prozessliste schreibt)
