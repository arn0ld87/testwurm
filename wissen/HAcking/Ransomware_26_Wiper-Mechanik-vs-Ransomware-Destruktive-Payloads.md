# Ransomware – Band 26: Wiper-Mechanik vs. Ransomware und Destruktive Payloads

Technischer Deep Dive: Wiper vs. Ransomware-Dichotomie, Scheinkryptographie, Fallstudien (NotPetya, WhisperGate, HermeticWiper), Low-Level Disk-I/O (MBR/GPT-Erase), krypto-forensische Erkennungsmatrix und Incident-Response-Triage.

---

## 1. Strategische und technische Dichotomie

Während kriminelle Ransomware-Akteure finanziell motiviert sind und eine funktionierende Entschlüsselung als Geschäftsgrundlage benötigen, verfolgen staatliche Akteure mit **Wipern** geopolitische und destruktive Ziele: Zerstörung von Infrastrukturen, Desinformation und irreversible Datenvernichtung.

```
+----------------------------------------------------------------------------+
| Ransomware vs. Wiper im technischen Vergleich                             |
+----------------------------------------------------------------------------+
| Merkmal               Echte Ransomware             Wiper / Scheinkrypto    |
+----------------------------------------------------------------------------+
| Primärziel            Geld / Erpressung            Maximale Zerstörung     |
| Krypto-Design         Hybride KEM (RSA/ECC + AES)  Einweg-Wipe / XOR / Null|
| Key-Retention         Session-Key wird asym.       Session-Key wird sofort |
|                       verschlüsselt gespeichert    verworfen oder genullt  |
| Lösegeldforderung     Echter Verhandlungskanal     Täuschung / Nebelkerze  |
| Wiederherstellbar     Ja (nach Zahlung/Key-Fund)   Mathematisch unmöglich  |
| Zerstörungsgrad       Dateiebene (Dateisystem intakt) MBR/GPT/MFT Raw Erase|
+----------------------------------------------------------------------------+
```

### 1.1 Scheinkryptographie als psychologische Waffe

Häufig tarnen Akteure Wiper als Ransomware (sogenannte **Pseudo-Ransomware**). Der gefälschte Erpresserbrief erfüllt taktische Zwecke:
- **Verzögerung der Incident Response:** Das Opfer glaubt, verhandeln zu können, und verzögert forensische Sicherungs- und Neuinstallationsmaßnahmen.
- **Tarnung von Sabotage als gewöhnliche Kriminalität:** Erschwert die politische Attribution an staatliche Akteure.

---

## 2. Fallstudien destruktiver Schadsoftware

### 2.1 NotPetya (2017) – Die Zerstörung des Salsa20-Schlüssels

NotPetya gab vor, die bekannte Petya-Ransomware zu sein. Petya verschlüsselte den Master File Table (MFT) mit Salsa20 und zeigte einen "Personal Installation Key" an, aus dem der Angreifer den Salsa20-Key ableiten konnte.

```
+-----------------------------------------------------------------------+
| Die krypto-forensische NotPetya-Täuschung                             |
+-----------------------------------------------------------------------+
| Echte Petya:                                                          |
|   Salsa20-Key (128 Bit) ---> ECC-Verschlüsselung mit Public Key       |
|   ---> Ausgabe als Base58-String (Installation Key)                   |
|   Ergebnis: Key ist durch den privaten Key der Angreifer berechenbar! |
|                                                                       |
| NotPetya (Wiper):                                                     |
|   Installation Key = CryptGenRandom(32 Bytes)                         |
|   Ergebnis: Die angezeigte ID besteht aus reinem Zufallsrauschen!     |
|             Der Salsa20-Key wurde nie gespeichert und existiert       |
|             an keinem Ort der Welt mehr. Wiederherstellung unmöglich!|
+-----------------------------------------------------------------------+
```

### 2.2 WhisperGate (2022) – Zweistufige Vernichtung

Im Januar 2022 gegen ukrainische Behörden eingesetzt:
- **Stage 1:** Schreibt einen böswilligen 16-Bit-Bootloader in Sektor 0 (`\\.\PhysicalDrive0`), der eine Lösegeldnachricht und eine Bitcoin-Adresse anzeigt.
- **Stage 2:** Parallel lädt die Malware einen destruktiven Downloader, der Dateien anhand einer festen Erweiterungsliste sucht und deren Inhalt mit einer festen statischen Bytefolge (`0xCC`) vollständig überschreibt.

### 2.3 HermeticWiper (2022) – Treiber-basierter Raw-Disk Erase

HermeticWiper nutzte einen legitimen, signierten Treiber einer Festplatten-Partitionierungssoftware (`EPMNTDR.SYS` von EaseUS), um Windows-Kernel-Schutzmechanismen zu umgehen (BYOVD - Bring Your Own Vulnerable Driver):
- Der Treiber ermöglichte uneingeschränkten direkten Sektorenzugriff auf physische Datenträger.
- HermeticWiper fragmentierte und überschrieb gezielt die Master Boot Record (MBR), Guid Partition Tables (GPT), Volume Boot Records (VBR) sowie die `$MFT` aller angeschlossenen SCSI-, IDE- und NVMe-Laufwerke.

---

## 3. Low-Level Disk-I/O Mechanik

Unter Windows schützt das Betriebssystem physische Sektoren vor unautorisiertem Zugriff aus dem User-Mode. Wiper setzen administrative Rechte ein, um ein Raw-Handle auf das physische Laufwerk zu öffnen:

```c
// Typischer C++ Aufruf zur Öffnung des physischen Datenträgers:
HANDLE hDisk = CreateFileW(
    L"\\\\.\\PhysicalDrive0",
    GENERIC_READ | GENERIC_WRITE,
    FILE_SHARE_READ | FILE_SHARE_WRITE,
    NULL,
    OPEN_EXISTING,
    0,
    NULL
);

if (hDisk != INVALID_HANDLE_VALUE) {
    // 1. Zerstörung des MBR (Sektor 0, 512 Bytes)
    BYTE zeroBuffer[512] = { 0 };
    DWORD bytesWritten = 0;
    WriteFile(hDisk, zeroBuffer, sizeof(zeroBuffer), &bytesWritten, NULL);

    // 2. Zerstörung des GPT Primary Headers (LBA 1, Sektor 1)
    // 3. Zerstörung der Partition Table Entries (LBA 2-33)
    // 4. Zerstörung des Backup GPT am physikalischen Plattenende
    CloseHandle(hDisk);
}
```

Nach dem Überschreiben der Partitionsdaten erzwingt die Schadsoftware den sofortigen Systemabsturz (BSOD) via `NtRaiseHardError` oder setzt das System über den Befehl:
```cmd
bcdedit /set {default} bootstatuspolicy ignoreallfailures & bcdedit /set {default} recoveryenabled no
```
in einen nicht mehr reparablen Boot-Loop.

---

## 4. Krypto-Forensische Erkennungsmatrix

Bei einem Incident muss das DFIR-Team innerhalb der ersten 60 Minuten entscheiden: **Handelt es sich um echte Ransomware oder um einen Wiper?**

```
+----------------------------------------------------------------------------+
| Forensische Triage-Entscheidungsmatrix                                     |
+----------------------------------------------------------------------------+
| Analyseschritt       Befund Echte Ransomware        Befund Wiper           |
+----------------------------------------------------------------------------+
| 1. Entropietest      Entropie ~7.99 (AES/ChaCha)    Entropie ~0.0 (Nullen) |
|                      Gleichmäßige Byte-Verteilung   oder konstantes Pattern|
|                                                                            |
| 2. Dateiende         Verschlüsselter Key-Block      Kein Footer vorhanden  |
|    (File Footer)     (128–512 Bytes Metadaten)      oder Müll-Bytes        |
|                                                                            |
| 3. Reverse-          Importiert Krypto-APIs         Nur WriteFile / I/O-API|
|    Engineering       Asymmetrischer Master-Key      Kein asymmetrischer Key|
|                      in der Binärdatei hinterlegt   im Code auffindbar     |
|                                                                            |
| 4. Partition Table   Partitionen intakt, Dateien    MBR/GPT gelöscht,      |
|    Status            besitzen neue Endung (.lock)   Dateisystem unlesbar   |
+----------------------------------------------------------------------------+
```

### 4.1 Entropie-Berechnung (Shannon-Entropie)

Forensiker berechnen die Entropie verdächtiger Dateien:
$$H(X) = -\sum_{i=0}^{255} P(x_i) \log_2 P(x_i)$$
- **$H \approx 7.95 - 8.00$:** Daten sind stark verschlüsselt oder komprimiert.
- **$H < 2.00$:** Daten wurden mit statischen Bytes (z. B. Nullen oder `0xCC`) überschrieben $\rightarrow$ **Zweifelsfreier Wiper-Befund**.

---

## 5. Incident Response Triage bei Wiper-Befall

Wird ein Angriff als Wiper identifiziert, ändert sich die Krisenstrategie fundamental:
1. **Keine Kontaktaufnahme:** Verhandlungen sind zwecklos, da technisch keine Entschlüsselungsschlüssel existieren. Jede Kontaktaufnahme verschwendet wertvolle Zeit.
2. **Sofortige Notfall-Trennung (Network Pull & Kill Power):** Da Wiper auf die Zerstörung von Backup-Appliances und Storages abzielen, müssen nicht betroffene Systeme sofort physikalisch getrennt werden.
3. **Bare-Metal Recovery:** Sämtliche betroffenen Festplatten müssen als kontaminiert und zerstört betrachtet werden. Wiederherstellung erfolgt ausschließlich über Offline-/Air-Gapped-Backups auf fabrikneuer Hardware oder nach vollständigem Secure Erase.

---

## Quellen
- [Q1] CyberDefenders – History of Ransomware: From Floppy Disk to RaaS
- [Q86] CISA / CERT-UA – Joint Advisory on HermeticWiper, CaddyWiper and WhisperGate
- [Q87] Kaspersky Lab – Technical Analysis: NotPetya is a Wiper, Not Ransomware
- [Q88] SentinelOne – Inside HermeticWiper: Anatomy of a Destructive Attack
