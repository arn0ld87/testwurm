# Ransomware – Band 9: Krypto-Implementierung und Datenformate

Programmiertechnischer Band: Bibliotheken, Chunking, Nonce-Disziplin, Fehlerklassen. Quellen am Ende.

## 1. Bibliothekswahl

| Bibliothek | Plattform | Stärken | Schwächen |
|---|---|---|---|
| **BCrypt / CNG** (`bcrypt.lib`) | Windows nativ | kein Drittanbieter-DLL-Abhängigkeit, AES-GCM/CTR aus dem OS, FIPS-Modus möglich | sperrige API, `NTSTATUS`-Fehlerbehandlung, Mode-Spezifika pro Algorithmus [1] |
| **libsodium** | Cross-Plattform | moderne Defaults (`crypto_aead_aes256gcm_*`, `crypto_aead_chacha20poly1305_*`, `crypto_kx_*`, `crypto_scalarmult` X25519), kleiner Footprint | AES-NI nicht überall verfügbar → ChaCha20-Fallback einplanen [2] |
| **OpenSSL 3.x** | Cross-Platform | breit, ML-KEM/Hybrid-Anbindung verfügbar | schwer, License-/Größen-Frage, deutlich mehr Binary-Fußabdruck (freie Einordnung) |
| **ring / RustCrypto** | Rust | auditierter Kern, `aes-gcm`/`chacha20poly1305`/`x25519-dalek` | Compile-Zeit, Feature-Flags nötig |

## 2. BCrypt konkret — die Fallstrücke

Aus der Funktionsreferenz [1]:
- Signatur: `BCryptEncrypt(hKey, pbInput, cbInput, pPaddingInfo, pbIV, cbIV, pbOutput, cbOutput, pcbResult, dwFlags)`
- **`pPaddingInfo` muss bei authetifizierten Modi auf `BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO` zeigen** — das ist der einzige Weg, AAD und Auth-Tag durchzureichen. `NULL` hier = keine Authenticated-Encryption-Semantik [1]
- **`BCRYPT_BLOCK_PADDING` darf bei authetifizierten Modi nicht gesetzt werden** [1]
- Ohne Padding-Flag muss `cbInput` ein Vielfaches der Blockgröße sein — bei Partial Encryption mit gekappten Blöcken ein realer Bruch (freie Einordnung)
- **`pbIV` wird von `BCryptEncrypt` verändert** — die IV-Größe kommt aus `BCryptGetProperty(BCRYPT_BLOCK_LENGTH)`. Wer die IV später braucht, muss sie vorher kopieren [1]
- `pbOutput == NULL` liefert die benötigte Puffergröße — nützlich für Buffer-Plan, aber **kein** Grund, zweimal zu verschlüsseln
- Sonderfall: `pbInput == pbOutput == NULL` bei AEAD behandelt Zero-Length-Daten als Auth-Operation (Tag kommt in `pPaddingInfo`)

**Praktischer Hinweis (freie Einordnung):** Bei CNG für AES-GCM pro Chunk ein frisches `BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO` mit `BCryptInitAuthInfo`-Muster bauen (Nonce, Tag-Buffer, AAD-Zeiger, Flags), sonst hängen sich Puffer-Zustände über Chunks hinweg aneinander — eine der häufigsten stillen Korruptionsquellen.

## 3. Nonce- und Key-Hygiene

- **AES-GCM:** Nonce-Wiederverwendung unter demselben Key bricht Vertraulichkeit **und** Integrität.libsodium empfiehlt, bei Client-Server-Protokollen entweder Richtungsschlüssel zu trennen oder in einer Richtung ein Bit zu maskieren / in der anderen zu setzen — dafür existiert die `crypto_kx_*`-API [2]
- **Key-Wechsel bei Datenvolumen:** libsodium empfiehlt, den Schlüssel zu wechseln, **bevor ~350 GB mit AES-GCM verschlüsselt sind** [2] — realistisch pro Host-Master, nicht pro Datei relevant, aber in einer Fileserver-Betrachtung schnell erreicht
- **ChaCha20-Poly1305 (libsodium):** 96-Bit-Nonce im IETF-Modus (`crypto_aead_xchacha20poly1305_irtf*` mit 192-Bit-Nonce) ist fehlertoleranter als die alte 64-Bit-Variante
- **Stream-Konstruktion für Dateien:** für nonce-basierte AEAD ist **STREAM** das passende Schema (Nonce = zufälliger Prefix + Zähler + Final-Flag), CHAIN nur für misuse-resistant AEAD. STREAM-Varianten nutzen u. a. `age`, Google Tink, Miscreant, Kryptor [4]

**Warum Chunks durchnummeriert werden müssen** [4]: Ohne in AAD oder Nonce eingebetteten Chunk-Index sind **Chunk-Umsortierung und -Duplizierung** unentdeckbar, ohne Endmarker oder Final-Flag sind **Trunkierungsangriffe** (Anhänger schneidet die letzten Chunks ab) unentdeckbar. Ein korrekt gebautes Format bindet:

```
AAD = Pfad-Relativpfad || Datei-ID || Chunk-Index || Final-Flag
Nonce = 12 B, pro Chunk deterministisch aus Per-File-Nonce + Counter
Tag  = 16 B, pro Chunk; zusätzlich Final-Tag über die Chunk-Gesamtheit
```

**Trunkierungsschutz explizit** [5]: Endmarker/Manifest-Länge mit signieren, sonst kann ein Angreifer die Datei kürzer machen, ohne dass eine AEAD-Prüfung anschlägt.

## 4. Referenz-Key-Schedule (freies Design, deckt sich mit realen Familien)

```
Operator-Master  (Server, verlässt nie den Key-Escrow)
      │  wrapt
      ▼
Host-Key-Wrap  ← KEM: X25519 ⊕ ML-KEM-768, Shared Secret → HKDF-SHA-256(infoder)
      │
      ▼
Per-File-DEK (32 B, zufällig)
      │  AES-256-GCM / ChaCha20-Poly1305, chunked
      ▼
Kiphertext + Per-Chunk-Tags + Footer mit gewrappter DEK
```

**Realbeispiel Lynx** [6]: ephemerer X25519-Schlüssel pro Datei → Curve25519 Shared Secret → **SHA-512 darüber** → AES-Key → AES-CTR, Nonce pro Block incrementiert, Marker am Dateiende. Check Point dokumentiert für **Akira Rust/ESXi** denselben Grundgedanken mit anderen Primitives.

**Freie Einordnung zu SHA-512 als KDF:** als Key-Derivation aus einem frischen ECDH-Secret ist SHA-512 vertretbar (kein Passwort-Härtungsfall), sauberer ist HKDF-SHA-256 mit Info-String — vor allem weil HKDF den Kontext (Host-ID, Datei-ID) bindet und so Schlüsselkontextverwechslungen verhindert.

## 5. Datenformat — was in den Header/Footer gehört

Pflichtfelder (freie Einordnung, konsistent mit [6]):

| Feld | Warum |
|---|---|
| Format-Version + Magier | Migrationsfähigkeit; sonst ist jeder Decryptor-Update ein Totalbruch |
| Public Key / KEM-Ciphertext | Wiederherstellungspfad |
| Per-File-DEK-Wrap | skalierbarer Key-Export statt Einzelfall-Rückgabe |
| Nonce-Basis + Chunk-Größe | Decryptor darf raten müssen, was er sehen muss |
| Verschlüsselte Bereichsliste | Teilverschlüsselung ist ohne explizite Range-Liste nicht deterministisch rekonstruierbar |
| Original-Dateigröße + Originalname/Extension | Restore ohne Manifest möglich |
| Chunk-Gesamtzahl + Final-Tag | Trunkierungsschutz |
| Host-ID / Victim-ID | Zuordnung in der Steuerungsapp |

**Warum Range-Listen no­twendig sind:** Eine Datei „Kopf 1 MB + Blöcke alle 5 MB" ist ohne Liste **nicht** eindeutig rekonstruierbar, wenn irgendwo die Dateigröße oder Blockgröße anders interpretiert wird. Lynx codiert Blockgröße, Blockschritt und übersprungene Blöcke im Marker [6] — das ist die Minimalform; eine echte Range-Liste ist robuster.

## 6. Krypto-Fehlerklassen im Betrieb

| Fehler | Ursache | Auswirkung | Gegenmaßnahme |
|---|---|---|---|
| Nonce-Wiederverwendung | Counter nicht zurückgesetzt, Prozess-Neustart ohne Resume-Log | Vertraulichkeit + Integrität gebrochen | Nonce-Basis pro Datei/Zweig, Manifest schreiben **vor** erstem Write |
| Buffer-Größe ohne Tag gerechnet | AEAD schreibt `len(plain) + tagLen` | Pufferüberlauf / abgeschnittener Tag | immer `+CRYPTO_AEAD_TAGLEN` reservieren |
| IV/Object-Zustand über Chunks gemerkt | `BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO` wiederverwendet | stille Korruption ab Chunk 2 | pro Chunk neu initialisieren [1] |
| In-place-Update ohne `pcbResult`-Prüfung | Teilweise Verarbeitung nicht bemerkt | Loch in Datei | Rückgabewert **und** Bytezahl prüfen |
| Partial-Write bei Disk-Full | Schreibabbruch mitten im Chunk | unrekonstruierbare Datei | Journal + `FlushFileBuffers` + Commit-Flag pro Datei |
| Key im Plaintext auf Disk | `key.bin` neben Daten | Zahlung nutzlos, Forensik-Geschenk | Wrap raus, Plaintext-Key nur flüchtig |

## 7. Was ein Decryptor zwingend können muss

1. **Idempotent** — zweimal laufen lassen ist erlaubt, drittes Mal ebenso.
2. **Ohne Netzwerk** — Key-Import aus lokalem Blob; sonst hängt Recovery an der Erreichbarkeit des Servers.
3. **Trockenlauf** — `--dry-run` mit Report, welche Dateien er anfassen würde.
4. **Range-aware** — bei Teilverschlüsselung die Bereiche kennen, sonst schreibt er Müll zurück.
5. **Verifikation pro Chunk** — Tag-Check vor Restore, sonst wird aus Verschlüsselung Datenverlust.
6. **Manifest-Fallback** — wenn das Manifest fehlt, aus Footer rekonstruieren (und umgekehrt).

## Quellen

- [1] Microsoft Learn – BCryptEncrypt (bcrypt.h): https://learn.microsoft.com/en-us/windows/win32/api/bcrypt/nf-bcrypt-bcryptencrypt
- [2] libsodium – AES256-GCM: https://libsodium.gitbook.io/doc/secret-key_cryptography/aead/aes-256-gcm
- [4] Crypto StackExchange – Encrypting arbitrary large files in AEAD chunks, how to protect against chunk reordering (STREAM vs CHAIN): https://crypto.stackexchange.com/questions/106983/encrypting-arbitrary-large-files-in-aead-chunks-how-to-protect-against-chunk-r
- [5] BitAtlas – Streaming Encryption for Large File Uploads (HKDF pro Datei, Per-Chunk-Nonce, Truncation-Schutz): https://bitatlas.com/blog/streaming-encryption-large-file-uploads
- [6] Nextron Systems – In-Depth Analysis of Lynx Ransomware (Curve25519 → SHA-512 → AES-CTR, 116-Byte-Marker): https://www.nextron-systems.com/2024-10-11/in-depth-analysis-of-lynx-ransomware/
- Querverweis: Band 03 §2 (Architektur), Band 08 §7 (Markerlayout), Band 10 (Key-Escrow in der App)
