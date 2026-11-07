# Ransomware – Band 19: Krypto-Forensik, Key-Recovery und Decryptor-Bau

Forensischer und defensiver Band: RAM-Analyse, Key Schedules, Krypto-Fehler realer Malware und sichere Decryptor-Architektur. Quellen am Ende.

## 1. Grundsatz der Krypto-Forensik: Wenn die Mathematik nicht hilft

Wurde eine Ransomware mit modernen kryptographischen Primitiven (AES-256-GCM, ChaCha20-Poly1305, Curve25519) mathematisch korrekt implementiert, ist ein Brute-Force-Angriff auf den Schlüsselraum ($2^{256}$ Operationen) nach den Gesetzen der Thermodynamik unmöglich.

Dennoch gelingt es Sicherheitsforschern (CERTs, BSI, No More Ransom, Emsisoft, Kaspersky), für zahlreiche Ransomware-Familien kostenlose Entschlüsselungswerkzeuge bereitzustellen. Jede erfolgreiche Entschlüsselung ohne Lösegeldzahlung beruht auf **mindestens einem von drei Faktoren**:

1. **Flüchtige Schlüssel im Arbeitsspeicher (RAM-Forensik vor Prozessende).**
2. **Kryptographische Implementierungsfehler der Malware-Entwickler.**
3. **Beschlagnahmte Server / Master-Key-Leaks bei Strafverfolgungsoperationen (z. B. Operation Cronos).**

---

## 2. RAM-Forensik & Key-Schedule-Rekonstruktion

Die wirksamste Sofortmaßnahme bei einem aktiven Ransomware-Befall lautet: **Systeme nicht ausschalten und nicht neustarten!** 
Wird der Strom gekappt, verflüchtigt sich der RAM-Inhalt, und die letzte Chance auf Schlüsselrettung ist verloren.

### 2.1 AES Key Schedule Invarianten & `aeskeyfind`
Wird AES im Kernel oder Userland ausgeführt, kann die CPU den 128- oder 256-Bit-Schlüssel nicht direkt auf Daten anwenden. Er muss über den **Rijndael Key Schedule** in Runden-Schlüssel expandiert werden (10 Runden für AES-128, 14 Runden für AES-256):
- Ein expandierter 256-Bit-Schlüssel belegt **240 Bytes zusammenhängenden Speicher**.
- Die Beziehung zwischen aufeinanderfolgenden Runden-Schlüsseln ist strikt mathematisch determiniert (durch Byte-Rotation `RotWord`, S-Box-Substitution `SubWord` und Rundenkonstante `Rcon`).

**Das forensische Prinzip:**
- Tools wie `aeskeyfind` scannen rohe RAM-Dumps (erzeugt via `winpmem`, `DumpIt` oder VM-Snapshot `.vmss`/`.vmsn`) nach diesen 240-Byte-Rijndael-Mustern.
- Selbst wenn Teile des Speichers überschrieben wurden: Aus **zwei beliebigen aufeinanderfolgenden Runden-Schlüsseln** kann der originale Master-Schlüssel mathematisch exakt rückwärts berechnet werden!

### 2.2 ChaCha20 State Matrix im Heap
ChaCha20 arbeitet auf einem 64-Byte-Zustandsblock (16 × 32-Bit Integer):
```
[ "expa" ] [ "nd 3" ] [ "2-by" ] [ "te k" ]  <- Konstanten (0x61707865, 0x3320646e, ...)
[ Key 0  ] [ Key 1  ] [ Key 2  ] [ Key 3  ]  <- 256-Bit Key (Bytes 0..15)
[ Key 4  ] [ Key 5  ] [ Key 6  ] [ Key 7  ]  <- 256-Bit Key (Bytes 16..31)
[ Block  ] [ Nonce0 ] [ Nonce1 ] [ Nonce2 ]  <- Zähler & 96-Bit Nonce
```
- Viele unausgereifte Malware-Builds rufen nach der Verschlüsselung zwar `free(state)` auf, vergessen aber `SecureZeroMemory()` oder `sodium_memzero()`.
- Der 64-Byte-Block mit den charakteristischen ASCII-Konstanten `"expand 32-byte k"` verbleibt als unbereinigtes Residuum im unallokierten Heap-Speicher und kann per YARA-Regel isoliert werden.

---

## 3. Reale Krypto-Fehler in Ransomware-Familien

Entwickler von Schadsoftware sind häufig Programmierer ohne fundierte kryptographische Ausbildung. Typische historische Fehlerklassen:

### Fehlerklasse 1: Schwache PRNGs und vorhersagbare Seeds
- **Der Fehler:** Das Implantat generiert symmetrische Schlüssel mit einfachen Bibliotheksfunktionen:
  ```c
  srand(time(NULL));
  for(int i = 0; i < 32; i++) key[i] = rand() % 256;
  ```
  Oder unter Windows:
  ```c
  DWORD seed = GetTickCount(); // Millisekunden seit Systemstart
  ```
- **Die Ausnutzung:** Der Seed `time(NULL)` liefert nur einen einzigen Wert pro Sekunde. Kennt der Forensiker den Zeitstempel der Datei-Modifikation (aus `mtime`), umfasst der Suchraum für den Seed oft weniger als 60 Sekunden ($N = 60$). Ein Brute-Force-Skript prüft 60 Keys und entschlüsselt die Datei binnen Millisekunden (historisch: *Petya*, frühe *GandCrab*-Varianten).

### Fehlerklasse 2: Nonce-Wiederverwendung in Stream Ciphers & AEAD
Wird ChaCha20, AES-CTR oder AES-GCM mit statischer Nonce betrieben:
$$C_1 = P_1 \oplus 	ext{Keystream}(K, N), \quad C_2 = P_2 \oplus 	ext{Keystream}(K, N)$$
$$C_1 \oplus C_2 = P_1 \oplus P_2$$
- Ist der Klartext von $P_1$ bekannt (Known Plaintext, z. B. standardisierter Header einer PDF- oder DOCX-Datei), berechnet sich der Keystream direkt zu:
  $$	ext{Keystream} = C_1 \oplus P_1$$
- Dieser Keystream entschlüsselt sofort alle anderen Dateien $C_2, C_3, \dots$, die mit demselben Schlüsselpaar verschlüsselt wurden.
- **Bei AES-GCM:** Nonce-Wiederverwendung erlaubt zusätzlich die Fälschung des GHASH-Authentifizierungs-Tags.

### Fehlerklasse 3: Schlüssel-Trunkierung und Range-Fehler
- **Beispiel Babuk (2021):** Babuk nutzte Curve25519. In einer Version wurde der private Schlüssel vor der Multiplikation in einen Festpuffer kopiert, wobei Null-Terminatoren (`\0`) den Puffer vorzeitig abschnitten.
- **Beispiel DeadBolt (2022):** Ein Typumwandlungsfehler in Go führte dazu, dass der Schlüssel aus einem verkürzten Byte-Array abgeleitet wurde, wodurch der effektive Schlüsselraum drastisch sank.

---

## 4. Sichere Decryptor-Architektur (No More Ransom Methodik)

Ein Entschlüsselungsprogramm (Decryptor) trägt ein ebenso hohes Schadenspotenzial wie der Encoder selbst: **Wird eine Datei mit falschem Schlüssel oder falschem Offset entschlüsselt, wird sie irreversibel korrumpiert.**

### Die Invarianten eines professionellen Decryptors

```
┌────────────────────────────────────────────────────────┐
│               Sicherheitsarchitektur Decryptor         │
└────────────────────────────────────────────────────────┘
  1. Pre-Flight Check:
     - Ausreichend freier Speicherplatz für Backups vorhanden?
     - Ist der Entschlüsselungsschlüssel valide (Validierung an Testvektor)?

  2. Datei-Identifikation:
     - Matcht die Dateiendung (z. B. .locked)?
     - Magic Bytes im Header vorhanden (Marker-Prüfung)?

  3. Integritäts- und Tag-Prüfung VOR dem Überschreiben:
     - Entschlüsselung in temporären Speicherpuffer
     - Ist der GCM-/Poly1305-Tag valide?
     - Wenn Tag ungültig: ABBRUCH, Datei nicht anfassen!

  4. Nicht-destruktives Schreiben:
     - Entschlüsselte Datei unter Originalnamen neu schreiben (.pdf statt .pdf.locked)
     - Erst nach erfolgreichem Hash-Abgleich die .locked-Datei löschen
     - Transaktions-Logbuch führen (Crash-Resistenz gegen Stromausfall)
```

---

## 5. Entropie-Analyse & Erkennung verschlüsselter Dateien

Forensiker müssen oft automatisiert scannen, welche Dateien auf einem Storage tatsächlich verschlüsselt wurden und welche intakt geblieben sind.

### Shannon-Entropie
$$H(X) = -\sum_{i=0}^{255} P(x_i) \log_2 P(x_i)$$
- **Skala:** $0.0$ (völlig monotone Daten, z. B. nur Nullbytes) bis $8.0$ (vollkommene Zufallsverteilung).
- **Verschlüsselte Daten:** Eine kryptographisch starke Verschlüsselung (AES, ChaCha20) erzeugt Daten mit einer Entropie von **$7.95$ bis $8.00$** und bestandener Chi-Quadrat-Gleichverteilung.
- **Abgrenzung zu komprimierten Daten (ZIP, JPEG, MP4):**
  - Auch komprimierte Dateien besitzen hohe Entropie ($7.2$ bis $7.8$).
  - **Unterscheidungsmerkmal:** Komprimierte Dateien besitzen am Dateianfang feste Magic Bytes (z. B. `PK\x03\x04` für ZIP, `\xFF\xD8\xFF` für JPEG). Fehlen diese bekannten Header und liegt die Entropie über $7.98$, handelt es sich mit $99.9\%$ Wahrscheinlichkeit um Ciphertext.

---

## Quellen

- No More Ransom Initiative (Europol, Dutch National Police, Kaspersky, McAfee): Decryptor Design Standards.
- Emsisoft Malware Lab: Ransomware Decryption Guidelines & Pitfalls.
- Volatility Foundation: Memory Forensics with Volatility 3 – Extracting Crypto Keys from Volatile Memory.
- BSI: Leitfaden zur Reaktion auf Ransomware-Vorfälle für Unternehmen und Behörden.
- Halderman et al.: Lest We Remember – Cold Boot Attacks on Encryption Keys (USENIX Security).
