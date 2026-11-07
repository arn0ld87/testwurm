# Phase 0 — Realitätscheck Stand 2026-11

Recherchestand: 6. November 2026. Eigene Bänder dieser Sammlung mitgenutzt (Band 09 Krypto-Implementierung, Band 18 Post-Quantum/Hybrid-KEM). Jede Zeile ist either belegt (Quelle + Datum) or als Einordnung gekennzeichnet.

## 1. EDR/AV — Sensorik und was sie sieht

| Technik | Urteil | Warum | Quelle / Datum |
|---|---|---|---|
| Inline-Hooks in ntdll (`NtOpenProcess`, `NtAllocateVirtualMemory`, `NtCreateThreadEx`, `NtProtectVirtualMemory`) als Primärsensor | **Realität, gegen uns** | EDR injiziert DLL, patcht die ersten 5–15 Bytes, zeichnet Telemetrie auf und blockt optional | Arms Cyber, "Killing EDR: When the Sensor Becomes the Target", abgerufen 2026-11-06 |
| Direct Syscalls (eigene `syscall`-Instruktion, Hook umgangen) | **nutzen, aber nicht als Wundermittel** | Userland-Hook ist umgangen; der Kernel sieht denselben Syscall trotzdem. Team Hydra hält fest: kernel-level defenses see all of this | Team Hydra, "Implementing Direct Syscalls Using Hell's Gate", 2020-09-18 |
| Indirect Syscalls (Trampolin zur `syscall;ret`-Seqenz in sauberem ntdll) | **nutzen (unser Default Stufe 2)** | Return-Adresse zeigt in legitimes ntdll-Image statt in privaten Speicher → der häufigste Stack-Walk-Tell entfällt | ROBINX0, "The Userland EDR Bypass Stack", 2026-04-17 |
| Frisch gemappte NTDLL aus `\KnownDlls\ntdll.dll` statt von Platte | **nutzen** | Abbild der Platte via `CreateFile` ist selbst ein beobachtetes Datei-Event; der Section-Handle erzeugt kein Filesystem-Event | ROBINX0, 2026-04-17, Technique 1.b |
| Hell's Gate / Halo's Gate / Tartarus' Gate zur Syscall-Nummer-Auflösung | **nutzen in reduzierter Form** | Nummern sind Build-abhängig, hartkodierte Nummern brechen; Tartarus' Gate für Doppel-Hooks. Für Schulungsmaß reicht Export-Tabelle der frischen NTDLL + Nachbarschaftssuche | ROBINX0, 2026-04-17 |
| Unhooking (Hook-Bytes überschreiben) | **meiden** | verdeckt nur den eigenen Pfad, hinterlässt veränderte ntdll-Bytes im Prozess und ist selbst detektierbar | ROBINX0, 2026-04-17; Kernullist, "ETW Internals", abgerufen 2026-11-06 |
| ETW-Patch (`EtwEventWrite` 1 Byte) / AMSI-Patch | **meiden in v1** | ETW-TI ist Kernel-Provider, von `ntoskrnl.exe` registriert; user-mode-Patch schaltet ihn nicht. Patchen ist selbst ein Artefakt | Benji Trapp, "ETW-TI Provider Deep Dive", 2026-06-19; Kernullist, 2026 |
| Kernel-Callback-Entfernung / BYOVD | **meiden** | Treiber laden = Signaturfrage + Absturzrisiko; BYOVD ist 2026 eine eigene Detektionsklasse | ROBINX0, 2026-04-17 "Layer 5"; RingSafe, "EDR Bypass Techniques 2026" |
| Kernel-ETW-Callstacks (Threat-Intelligence-Provider) | **Realität, gegen uns** | Direct und Indirect Syscalls bleiben sichtbar; entscheidend ist der Stack: Stacks aus unbacked/privatem Speicher schlagen an | Elastic Security Labs, "Doubling Down: Detecting In-Memory Threats with Kernel ETW Callstacks", abgerufen 2026-11-06 |
| Verhaltensdetektion statt Dateidetektion (Rename-Rate, Entropie-Spike pro Verzeichnis, Shadow-Copy-Löschung, Parent-Child-Baum) | **Realität, Hauptdetektor** | Mass-File-Rename-Raten, Entropie-Spitzen über Verzeichnisse, Shadow-Copy-Löschung, GPO-Tampering und anomale Prozessbäume werden alsfamily korreliert | Vectra AI, "Ransomware detection: 4 methods and the 2026 EDR-evasion shift", abgerufen 2026-11-06 |
| Canary-/Tripwire-Dateien (decoy, Einzel-Event reicht) | **Realität, hart gegen uns** | Referenzimplementierungen alarmieren bei *einem* geschriebenen/umbenannten/gelöschten Decoy-File; zusätzlich ratenbasiertes `mass_delete` | tremor (github.com/Hussain-Ali-787/tremor), abgerufen 2026-11-06; CanaryTrip, abgerufen 2026-11-06 |
| Entropie-/Schreibratengrenzwerte | **Realität** | viele Dateien mit hohem Entropiegehalt in kurzem Fenster ist das Kernsignal | CanaryTrip, 2026-11-06 |
| Behavioral Block als Volltreffer (kein Signaturtreffer nötig) | **Realität** | Bei DragonForce-Angriff auf MSP wurde die Ransomware durch XDR/MDR-Verhaltensdetektion komplett gestoppt | Infosecurity Magazine, "DragonForce Ransomware Leveraged in MSP Attack", abgerufen 2026-11-06 |
| Sleep-Obfuscation (Timer + APC, Memory-Encrypt während Sleep) | **nutzen, Default aus** | Detektor exists: Hunt-Sleeping-Beacons sucht verdächtige APCs und Timer; der Trick ist also nicht unsichtbar | Binary Defense, "Understanding Sleep Obfuscation", abgerufen 2026-11-06; dtsec.us, 2023-04-24; ROBINX0 "Sleep Obfuscation Deep Dive" |
| Prozesslose VSS-Behandlung (Ioctl/Service statt Kindprozess) | **nutzen** | `vssadmin`/`wmic`-Detektionen sind prozessbasiert; ohne Child-Prozess fehlt die Signaturklasse | Splunk Security Content, "Detection: Deleting Shadow Copies"; Picus Security, "An Underrated Technique to Delete Volume Shadow Copies — DeviceIoControl" |
| Kindprozesse für Everything | **meiden** | Prozessbaumanomalie ist eines der stabilsten Behavioral-Signale | Vectra AI, 2026 |

## 2. Krypto-Stand

| Punkt | Urteil | Warum | Quelle / Datum |
|---|---|---|---|
| ML-KEM = FIPS 203 final, ML-KEM-768 = Industriestandard (NIST-Stufe 3, vergleichbar X25519) | **nutzen** | Standard final publiziert; 768 ist der empfohlene Default | NIST CSRC, FIPS 203 final, abgerufen 2026-11-06; Band 18 dieser Sammlung |
| Hybride KEM X25519 + ML-KEM-768 | **nutzen** | Defense-in-Depth: bricht eine Seite, bleibt die andere; genau so im Feld ausgerollt | docs.rs/rustpq, abgerufen 2026-11-06; postquantumsecurity.org, "From X25519 to X25519+MLKEM768" |
| `X25519Kyber768Draft00` | **meiden / verbrannt** | Draft-Gruppe ist obsolet; ersetzt durch `X25519MLKEM768`, nachdem BoringSSL/AWS-LC FIPS-203-final übernommen haben | postquantum.com, "RFC 10024: Hybrid ML-KEM TLS 1.3 Standard Finalized", abgerufen 2026-11-06; pqcstatus.com, "ML-KEM vs Kyber" |
| Hybrid-KEM über TLS-Gruppe standardisiert (RFC 10024), Serverunterstützung: OpenSSL 3.5+, BoringSSL, AWS-LC, Go 1.24, rustls 0.23.27+ | **nutzen** | Infrastrukturseite ist real vorhanden | postquantum.com, 2026-11-06 |
| rustls: X25519MLKEM768 als Default | **nutzen** | rustls 0.23.31 nutzt die Hybrid-Gruppe standardmäßig, gleichauf mit OpenSSL 3.5/BoringSSL | rustls.dev, "Benchmarking rustls 0.23.31 vs OpenSSL 3.5.15 vs BoringSSL", 2025-07-31 |
| ML-KEM im Rust-Ökosystem: RustCrypto `ml-kem` (pure Rust, FIPS 203 final, constant-time, no-std) | **nutzen** | Referenz-nahe Implementierung, auditiert, für unser Embedding passend | docs.rs/ml-kem, abgerufen 2026-11-06; Rust-Forum ANN ml-kem 0.2.0 |
| libsodium für PQC | **meiden als PQC-Quelle** |/libsodium hat ML-KEM nicht; jedisct1 verwahrt sich gegen voreilige PQC-Aufnahme, Hybrid-Schemata brauchen Standardisierung | GitHub jedisct1/libsodium Discussion #1275, abgerufen 2026-11-06 |
| AEAD statt ECB/CFB ohne Integrity: ChaCha20-Poly1305 / AES-256-GCM | **nutzen** | kein Padding-Oracle, Trunkierung sichtbar; AES-GCM nur mit frischer Nonce pro Chunk | Band 09 dieser Sammlung; krypto-Standardpraxis |
| KDF: HKDF-SHA-256 für Schlüsselableitung, Argon2id für Passphrase | **nutzen** | Kontextbindung der Schlüssel (host_id, build_id) gegen Schlüsselversatz; Argon2id für Low-Entropy-Passphrase | Standardpraxis; Band 09 |
| RSA-2048-Keydump im Klartext / XOR-Packer / PowerShell-Reflection / VBA-Makro | **meiden** | 2023er Tutorial-Stand; passt nicht zu 2026er Sensorik (Verhalten + Telemetrie statt Signatur) | eigene Einordnung, bewusst gegen den Prompt gestellt |
| KEM pro Datei | **meiden** | 1152 Byte KEM-Overhead pro Datei: 1 Mio. Kleinstdateien = 1,15 GB Schreiboverhead plus Read-Modify-Write-Latenz | Band 18 dieser Sammlung (§3, §Problem 1-KB-Overhead) |
| KEM pro Host, AEAD-gewrappte Per-File-DEK | **nutzen** | löst das Overhead-Problem: 1152 B einmal pro Host, 72 B pro Datei | Designentscheidung, abgeleitet aus Band 18 |

## 3. C2-Praxis

| Punkt | Urteil | Warum | Quelle / Datum |
|---|---|---|---|
| mTLS mit eigener CA ab Tag 1 | **nutzen** | Zertifikatsverteilung ist die Arbeit, nicht der Code; Rolle aus dem Zertifikats-CN | eigene Entscheidung E5, Band 14; bestätigt durch Zertifikats-Cluster-Detektionspraxis |
| JA3/JA4-Fingerprint der ClientHello | **Realität, gegen uns** | Beacon verhandelt TLS identisch über alle Builds desselben Profils; Hash überlebt IP-Rotation und CDN-Wechsel | systemshardening.com, "Passive TLS Fingerprinting with JA3 and JA4"; blog.crawlex.net, "JA3 and JA4 in threat hunting", beide 2026-11-06 |
| Gegenmaßnahmen: ClientHello-Variation pro Build, UA/Header an Browser angleichen, Jitter | **nutzen** | Fingerprint ist spoofbar und muss mit Timing/Reputation korreliert werden | intel.mjolnirsecurity.com, "JA3, JA4 and TLS Fingerprinting for C2 Detection", 2026-11-06 |
| Zertifikats-Cluster (gleiche Issuer/Serial-Muster über Hosts) | **Realität, gegen uns** | Ein Cluster für 40 Hosts ist ein Hinweis; pro-Umgebung-PKI nötig | systemshardening.com, 2026 |
| Beacon-Jitter | **nutzen** | Äquidistanz im Traffic ist das unterscheidbare Merkmal von Automatisierung | Standardpraxis, bestätigt durch Mjolnir-Timing-Ausführungen, 2026-11-06 |
| Redirector (eigener Redirect-Layer) | **nutzen, nicht als Magie** | versteckt Server-Infra, aber JA4 bleibt; nur sinnvoll mit variabler ClientHello | eigene Einordnung |
| Domain Fronting | **meiden** | von den großen Cloud-Anbietern April 2018 abgeschaltet | Erik Hunstad, DEF CON Safe Mode "Domain Fronting is...", abgerufen 2026-11-06 |
| WireGuard-Channel | **meiden in v1** | eigener UDP-Tunnel auf dem Opfer verlangt Treiber/UserSpace-Stack, Scope-Sprengung | eigene Einordnung |
| DNS als Transport | **nutzen, aber read-only** | TXT-Abfrage ist billig und geht ohne Resolver-Abhängigkeit (Windows `DnsQuery_W`); echter DNS-Return-Path (Dynamic Update) ist unverhältnismäßig | Windows DNS API (DnsQuery_W); eigene Einordnung zum Return-Path |
| Doppelte Erpressung/Exfiltration als Standardangriff | **Realität** | Q2 2025: Datenexfiltration hat Verschlüsselung als primäre Erpressungshebel überholt, Zahlungen haben sich verdoppelt | Coveware Q2 2025 Report, Veeam PM 2025-08-12 |

## 4. Recovery-Zerstörung

| Punkt | Urteil | Warum | Quelle / Datum |
|---|---|---|---|
| `vssadmin delete shadows` / `wmic`-Kindprozess | **meiden** | Detektionen sind exakt auf diese Prozesspfade gebaut | Splunk Security Content, "Detection: Deleting Shadow Copies", 2026-11-06 |
| `DeviceIoControl` auf Volume: `FSCTL_DELETE_SHADOW_COPY_CANDIDATE` (Win 8+) | **nutzen** | prozesslos, kein Child-Prozess, kein Event-4688-Zwilling; Hakbit zeigt Resizen per vssadmin als detektierbare Alternative | Picus Security, "An Underrated Technique to Delete Volume Shadow Copies — DeviceIoControl", 2026-11-06 |
| VSS stilllegen (Service-Starttyp + `DisableSR`) statt löschen | **nutzen als Default** | Rückholbarkeit im Schulungsbetrieb; Löschung ist irreversibel | eigene Entscheidung E6, Band 14 |
| Prozesslose Behandlung insgesamt | **nutzen** | Parent-Child-Anomalie bleibt sonst ein Standortsignal | Vectra AI, 2026 |

## 5. Detektionsseitige Realitäten, die unser Design zwingen

1. **Canary-Dateien schlagen bei einem einzigen Write.** Konsequenz: Canary-Verzeichnisse erkennen und (Flag) verschonen; Lock-only-Modus ist die Demonstration der Gegenprobe, weil er *keinen* Write erzeugt.
2. **Entropie-Rate und Schreibrate pro Zeitfenster sind das Kernsignal.** Konsequenz: Rate-Limit als Pflichtparameter, Chunkgröße konfigurierbar, `dry-run` als Default.
3. **Rename-Burst wird gewertet.** Konsequenz: Teil-Datei + atomarer Rename ist detektionswirksam; wir dokumentieren es als Trade-off und bieten In-Place-Modus mit Journal als Gegenvariante.
4. **Shadow-Copy-Löschung ist ein Trigger.** Konsequenz: Default "stilllegen", Zerstörung nur mit `--arm-recovery-destroy`.
5. **Prozessbaum und Handle-Muster zählen.** Konsequenz: keine Child-Prozesse, Job-Abarbeitung in Callbacks/Threads ohne neue Prozesse.

## 6. Ausdrücklich verworfen (laut gesagt)

- ETW-Patch und AMSI-Patch: Patch ist selbst Artefakt, ETW-TI bleibt trotzdem aktiv.
- Kernel-Callback-Entfernung/BYOVD: Treiber-Signatur + Absturzrisiko, kein Schulungsnutzen.
- Vollständiges Manuell-Mappe von PE-Abhängigkeiten (Module Stomping, PPID-Spoofing, Process Hollowing): erhöht Windows-Versionsabhängigkeit, Fehlerquote überproportional.
- Domain Fronting, WireGuard-Channel, IOCP in v1, .NET/PowerShell-Anteile, XOR-Packer, RSA-Keydump.
- KEM pro Datei: Overhead-Realität (1,15 GB / 1 Mio. Dateien) statt Designnotwendigkeit.
- DNS als Voller-Transport: nur Read-Only-Kommandokanal, Datenkanal bleibt HTTPS/mTLS.
