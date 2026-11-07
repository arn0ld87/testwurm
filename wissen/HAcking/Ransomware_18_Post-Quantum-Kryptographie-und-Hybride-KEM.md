# Ransomware – Band 18: Post-Quantum-Kryptographie und Hybride KEM

Kryptographischer und Implementierungsband: FIPS 203 ML-KEM-768, FIPS 204 ML-DSA, Hybrid-KEM-Formate und Header-Overhead. Quellen am Ende.

## 1. Hintergrund: Warum Post-Quantum im Ransomware-Kontext?

Klassische Ransomware stützt sich auf asymmetrische Public-Key-Kryptographie (RSA-2048, RSA-4096, Curve25519/Ed25519), um symmetrische Dateischlüssel (AES-256, ChaCha20) sicher vor Ort zu kapseln, ohne den privaten Hauptschlüssel auf dem Opfersystem preiszugeben (Band 03 & 09).

### Das HNDL-Paradigma (Harvest Now, Decrypt Later)
Mit dem Fortschritt im Quantencomputing und dem Shor-Algorithmus ist bekannt, dass ausreichend große fehlertolerante Quantencomputer (Q-Day) diskrete Logarithmen (ECDH/ECC) und Primfaktorzerlegungen (RSA) in polynomialer Zeit brechen können.
- Für Opfer von Ransomware bedeutete dies bislang theoretisch: Verschlüsselte Backups und Archive könnten in 10 bis 15 Jahren bei Verfügbarkeit von Quanten-Hardware nachträglich entschlüsselt werden.
- Für Angreifer (insbesondere Nation-State-Akteure oder hochentwickelte RaaS-Betreiber) bedeutet dies den Anreiz, **Post-Quantum Cryptography (PQC)** in ihre Implantate zu integrieren, um eine mathematische "Ewigkeitsverschlüsselung" zu garantieren.

---

## 2. NIST Post-Quantum Standards (FIPS 203 & FIPS 204)

Im August 2024 veröffentlichte das US-amerikanische National Institute of Standards and Technology (NIST) die finalen Standards für Post-Quantum-Kryptographie:

### FIPS 203: ML-KEM (Module-Lattice-based Key Encapsulation Mechanism)
- Basiert auf dem früheren Crystals-Kyber-Algorithmus.
- Mathematische Härte: **Module Learning with Errors (M-LWE)** auf algebraischen Gittern (Lattices).
- Bietet drei Sicherheitsstufen:
  - **ML-KEM-512** (NIST-Stufe 1, vergleichbar mit AES-128)
  - **ML-KEM-768** (NIST-Stufe 3, vergleichbar mit AES-192 und X25519; **Industriestandard und empfohlener Default**)
  - **ML-KEM-1024** (NIST-Stufe 5, vergleichbar mit AES-256)

### FIPS 204: ML-DSA (Module-Lattice-based Digital Signature Algorithm)
- Basiert auf Crystals-Dilithium.
- Dient der digitalen Signaturprüfung (z. B. zur Authentifizierung von C2-Kommandos und Entschlüsselungs-Authorisierungen).

---

## 3. Hybride KEM-Architektur (ML-KEM-768 + X25519)

In modernen Sicherheits- und Krypto-Designs wird PQC nicht isoliert eingesetzt, sondern als **hybrider Verbund (Dual-KEM)** mit bewährter klassischer Krypto (X25519).

### Warum Hybrid?
- **Sicherheitsgarantie:** Sollte in künftigen Jahren eine mathematische Schwachstelle in Gitter-Verfahren (Lattice-Krypto) entdeckt werden, schützt weiterhin die klassische X25519-Kurve. Bricht ein Quantencomputer X25519, schützt ML-KEM.
- **Formel:** Das Brechen des hybriden KEM erfordert das **gleichzeitige Brechen beider** mathematischen Probleme.

### Ablauf des hybriden KEM-Handshakes pro Datei/Batch

```
Angreifer-C2 / Master:
  Besitzt Private Keys: (sk_classic, sk_pq)
  Verteilt Public Keys im Implantat: (pk_classic, pk_pq)

Implantat vor Ort (Verschlüsselung):
  1. Erzeugt ephemeres X25519-Schlüsselpaar: (sk_eph, pk_eph)
  2. Berechnet klassisches Shared Secret:
     SS_classic = X25519(sk_eph, pk_classic)

  3. Führt ML-KEM-768 Encapsulation aus:
     (Ciphertext_pq, SS_pq) = ML-KEM-768-Encaps(pk_pq)

  4. Kombiniert beide Shared Secrets via HKDF (RFC 5869):
     IKM = SS_classic || SS_pq
     Key_file = HKDF-Extract-Expand(IKM, salt="Ransomware-Hybrid-KEM-v1", len=32)

  5. Verschlüsselt Datei-Chunks mit Key_file (AES-256-GCM oder ChaCha20-Poly1305).

  6. Schreibt Datei-Header:
     Header = [Magic (4B) || pk_eph (32B) || Ciphertext_pq (1088B) || AuthTag (16B)]
```

---

## 4. Dateiformat, Header-Overhead und Byte-Layout

Der Einsatz von Post-Quantum-Verfahren hat massive Auswirkungen auf das Datenformat, da Gitter-basierte Ciphertexte um ein Vielfaches größer sind als klassische elliptische Kurven:

| Parameter | Klassisch (X25519 ECIES) | Reines ML-KEM-768 | Hybrides KEM (X25519 + ML-KEM-768) |
|---|---|---|---|
| **Public Key Größe** | 32 Bytes | 1.184 Bytes | 1.216 Bytes |
| **Ciphertext / Ephemeral Data** | 32 Bytes (`pk_eph`) | 1.088 Bytes | **1.120 Bytes** (32B + 1.088B) |
| **Header-Gesamtgröße** | ~48–64 Bytes | ~1.120 Bytes | **~1.152–1.200 Bytes** |

### Das Problem des 1-KB-Overheads bei Kleindateien
Wenn ein Implantat 1 Million kleine Dateien (z. B. Quellcode, Textdateien, INI-Dateien mit 2–10 KB) einzeln mit hybridem KEM verschlüsselt:
- **Datenaufblähung:** 1.000.000 × 1.152 Bytes = **1,15 GB zusätzlicher Schreib-Overhead** allein für Header!
- **I/O-Verlangsamung:** Das Schreiben großer Header auf Festplatten mit 4-KB-Sektorgrößen führt zu Read-Modify-Write-Zyklen und massiven Latenzspitzen.

### Lösung: Hierarchisches KEM-Sharing (Directory-KEM)
Moderne Architekturen lösen diesen Konflikt durch hierarchische Schlüsselbäume:
1. **Verzeichnis-KEM:** Pro Verzeichnis oder pro Batch von 1.000 Dateien wird **ein einziges** hybrides KEM ausgeführt (Ersparnis: 1120 Bytes nur einmal pro Ordner).
2. **Dateiebene:** Für jede einzelne Datei wird ein Sub-Schlüssel abgeleitet:
   $$	ext{Key}_{file} = 	ext{BLAKE3-KDF}(	ext{Key}_{dir}, 	ext{File-UUID})$$
   Der Datei-Header schrumpft dadurch auf 16–32 Bytes zurück.

---

## 5. Performance und Implementierungs-Bibliotheken

### Bibliotheken im Praxiseinsatz
- **C/C++:** `liboqs` (Open Quantum Safe Project), offizielle NIST-Referenzimplementierung.
- **Rust:** `pqcrypto-kyber` / `ml-kem` Crates (reine No-Std-Implementierungen möglich).
- **Go:** `golang.org/x/crypto/mlkem` (offizieller Go-Standard ab Go 1.24).

### Performance-Benchmark (x86_64, AVX2-Optimierung)
Entgegen dem Vorurteil, Post-Quantum sei langsam, ist ML-KEM auf modernen x86_64- und ARM64-Prozessoren **extrem schnell**:
- **ML-KEM-768 Encapsulation:** ~15–25 Mikrosekunden (~20.000 CPU-Zyklen).
- **X25519 Scalar Multiplication:** ~30–50 Mikrosekunden.
- **Fazit:** Die KEM-Berechnung selbst ist schneller als klassisches X25519 oder RSA-4096. Der einzige Flaschenhals ist die Speicherbandbreite für die größeren Ciphertexte.

---

## 6. Forensische und Abwehr-Perspektive

1. **YARA- und Signaturerkennung:**
   - ML-KEM benötigt feste mathematische Konstanten für die Zahlentheoretische Transformation (Number Theoretic Transform, NTT):
     - Der Primmodul $q = 3329$.
     - NTT-Zeta-Wurzeln und Twiddle-Faktoren im Datenbereich.
   - Diese Tabellen bieten für Blue Teams hervorragende, unveränderbare **YARA-Signaturen**, um PQC-fähige Malware statisch zu erkennen.
2. **Entschlüsselbarkeit:**
   - Für die Incident Response ändert PQC nichts an der Ausweglosigkeit: Ein sauber implementiertes AES-256-GCM oder ChaCha20 mit ephemeralem KEM ist weder klassisch noch quantenmechanisch ohne den privaten Master-Schlüssel entschlüsselbar.

---

## Quellen

- NIST: FIPS 203 – Module-Lattice-based Key-Encapsulation Mechanism Standard (08/2024).
- NIST: FIPS 204 – Module-Lattice-based Digital Signature Standard (08/2024).
- Open Quantum Safe (OQS) Project: liboqs Reference Benchmarks & Hybrid KEM Specifications.
- BSI: TR-02102-1 Kryptographische Verfahren – Empfehlungen und Schlüssellängen (PQC-Migration).
- RFC 9180: Hybrid Public Key Encryption (HPKE) & RFC 5869 (HKDF).
