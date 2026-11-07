# Ransomware – Band 17: Cloud- und SaaS-Ransomware (Multi-Tier-Extortion)

Infrastruktur- und Strategieband: AWS S3 SSE-C Verschlüsselung, KMS-Swap, Entra ID PrivEsc und 4-Stufen-Erpressung. Quellen am Ende.

## 1. Verschiebung der Angriffsfläche: Vom Endpunkt in die Cloud

Die weit verbreitete Annahme, Cloud-Migration mache Unternehmen immun gegen Ransomware ("In AWS/Azure gibt es automatische Snapshots und Versionierung"), ist ein gefährlicher Trugschluss. Cloud-native Ransomware greift nicht primär Betriebssysteme virtueller Maschinen (EC2, Azure VM) an, sondern attackiert **die Managementebene (Control Plane), Identitäten und Speicherdienste** direkt über die Cloud-APIs.

### Primäre Eintrittsvektoren in Cloud-Umgebungen
- **Leaked Access Keys:** Auf GitHub/GitLab exponierte API-Schlüssel (`AKIA...`), in Docker-Images eingebrannte Secrets oder aus CI/CD-Pipelines (GitHub Actions, GitLab CI) entwendete Variablen.
- **SSRF in Web-Applikationen:** Ausnutzung von Server-Side Request Forgery zur Abfrage des Instance Metadata Service (IMDSv1 auf `http://169.254.169.254/latest/meta-data/iam/security-credentials/`), um temporäre STS-Rollen-Tokens abzugreifen.
- **Entra ID / M365 Password Spraying & MFA Fatigue:** Kompromittierung von Benutzerkonten und anschließende Eskalation über fehlerhafte Rollenzuweisungen.

---

## 2. AWS S3 SSE-C Attacken (Server-Side Encryption with Customer-Provided Keys)

Die technisch raffinierteste Ransomware-Technik in AWS basiert auf der legitimen AWS-Funktion **SSE-C (Server-Side Encryption with Customer-Provided Keys)**.

### Die Angriffsmechanik
Normalerweise verschlüsselt AWS S3 Objekte mit Schlüsseln, die in AWS KMS verwaltet werden (`aws:kms`). Bei SSE-C übergibt der Client beim Upload oder Kopieren jedoch seinen eigenen 256-Bit-AES-Schlüssel im HTTP-Header:
- Header: `x-amz-server-side-encryption-customer-key` (Base64-kodierter AES-256 Key)
- Header: `x-amz-server-side-encryption-customer-key-MD5`

```python
# Schematischer Ablauf einer SSE-C Ransomware-Attacke
import boto3

s3 = boto3.client('s3')
attacker_key = b"32-byte-long-secret-key-12345678"  # Key des Angreifers

# Für jedes Objekt im Opfer-Bucket:
s3.copy_object(
    Bucket='opfer-daten-bucket',
    CopySource='opfer-daten-bucket/vertraulich.pdf',
    Key='vertraulich.pdf',
    SSECustomerAlgorithm='AES256',
    SSECustomerKey=attacker_key,
)
```

### Warum SSE-C für Opfer fatal ist
1. **Kein KMS-Speicher:** AWS speichert den SSE-C-Schlüssel **an keiner Stelle**. Er wird nach der Ver-/Entschlüsselung im RAM des S3-Endpunkts sofort verworfen.
2. **Volle Sperrung:** Weder der Bucket-Eigentümer, der AWS Account Root User noch der AWS Enterprise Support können jemals wieder auf das Objekt zugreifen, wenn der Angreifer den Schlüssel vorenthält.
3. **Keine lokale Rechenleistung/Transfer:** Der Angreifer muss die Daten nicht über seine Internetverbindung herunterladen, lokal verschlüsseln und wieder hochladen. Der `CopyObject`-Befehl weist die AWS-Server an, die Datei **intern mit Gigabit-Geschwindigkeit** neu zu verschlüsseln.
4. **Verharmlosung in Logs:** Die Operation erscheint in CloudTrail als legitimer `CopyObject`-Call.

---

## 3. AWS KMS & Snapshot Sabotage

Verfügt der Angreifer über administrative Rechte im AWS-Konto (z. B. `AdministratorAccess` oder weitreichende `kms:*`-Berechtigungen):

### KMS Key Swap & Deletion
- **`kms:ScheduleKeyDeletion`:** Angreifer setzt die Löschfrist für alle kundeneigenen KMS-Schlüssel (KMS CMKs) auf das Minimum von 7 Tagen. Alle EBS-Snapshots, RDS-Datenbanken und S3-Buckets, die diesen Schlüssel nutzen, werden unzugänglich.
- **`kms:PutKeyPolicy`:** Sofortiger Ausschluss: Der Angreifer überschreibt die Key Policy mit einer expliziten `Deny`-Regel für alle IAM-Rollen und Benutzer des Opfers (inklusive des Root-Accounts), außer für seine eigene externe IAM-Rolle. Das System ist auf einen Schlag vollständig gelockt.

### Snapshot- und Backup-Zerstörung
- Aufruf von `ec2:DeleteSnapshot` und `rds:DeleteDBSnapshot`.
- Löschen von AWS Backup Vaults via `backup:DeleteRecoveryPoint` und `backup:DeleteBackupVault`.
- Anti-Forensik: `cloudtrail:StopLogging`, `cloudtrail:DeleteTrail` sowie das Löschen von S3-Access-Logs.

---

## 4. Azure und Microsoft Entra ID Vektoren

In Microsoft Azure und Microsoft 365 (M365) fokussieren Angreifer auf Service Principals und App Registrations:

### Kompromittierung von Service Principals
- App Registrations mit Rechten wie `Directory.ReadWrite.All`, `RoleManagement.ReadWrite.Directory` oder `AppRoleAssignment.ReadWrite.All` erlauben es Angreifern, sich selbst unbemerkt die Rolle `Global Administrator` zuzuweisen.
- Privileged Identity Management (PIM) wird umgangen, wenn permanente Zuweisungen statt berechtigter Aktivierungen existieren.

### Azure Key Vault Purge-Sabotage
- Schlüssel in Azure Key Vault besitzen standardmäßig einen Soft-Delete-Schutz (Aufbewahrungsfrist 90 Tage).
- **Schwachstelle:** Wenn die Eigenschaft **Purge Protection** nicht explizit aktiviert ist, kann ein Angreifer mit Rechten `Microsoft.KeyVault/vaults/keys/purge/action` den Befehl `PurgeKey` absetzen. Dies löscht den Schlüssel sofort und unwiederbringlich.

### M365 SharePoint / OneDrive Ransomware
- Skripte traversieren die Microsoft Graph API (`/v1.0/drives/.../root/children`).
- Dateien werden heruntergeladen, verschlüsselt und hochgeladen.
- Um den Versionsverlauf von M365 unbrauchbar zu machen, rufen Angreifer PowerShell-Cmdlets auf:
  ```powershell
  Set-SPOSite -Identity "https://tenant.sharepoint.com/sites/hr" -DenyAddAndCustomizePages 0
  ```
  Oder sie reduzieren das Major-Version-Limit auf 1 und überschreiben die Datei zweimal, womit alle historischen Schattenkopien gelöscht sind.

---

## 5. Das Modell der 4-Stufen-Erpressung (Multi-Tier Extortion)

Wirtschaftlich und operativ agieren moderne Ransomware-Gruppierungen (LockBit, BlackCat/ALPHV, Clop, Akira) nicht mehr als reine "Dateiverschlüsseler", sondern betreiben ein vierstufiges Erpressungsmodell:

```
Stufe 1: Lokale Verschlüsselung (Infrastruktur-Sperre)
   │
   ├──▶ Stufe 2: Datenexfiltration & DLS-Leak (Double Extortion)
   │       │
   │       ├──▶ Stufe 3: DDoS & Personelles Harassment (Triple Extortion)
   │       │       │
   │       │       └──▶ Stufe 4: Regulatorischer & Reputations-Druck (Quadruple Extortion)
```

### Stufe 1: Infrastruktur- und Datenverschlüsselung
- Blockieren des operativen Geschäftsbetriebs (Produktion, ERP, E-Mail).
- Ziel: Schaffen von akutem Zeitdruck beim Opfer.

### Stufe 2: Exfiltration & Dedicated Leak Sites (DLS)
- Vor Beginn der Verschlüsselung werden Gigabytes bis Terabytes an sensiblen Daten exfiltriert.
- Standardwerkzeug: `rclone` mit vorkonfigurierten Cloud-Speicher-Profilen (Mega.nz, Wasabi, DropBox, eigener S3-Storage).
- Veröffentlichung von "Proof-Packs" (Geschäftsführungs-Pässe, Verträge, Kundenlisten) auf Tor-.onion-Seiten.

### Stufe 3: DDoS und direktes Harassment (Triple Extortion)
- **DDoS:** Lastangriffe auf die öffentlichen Webseiten, Kundenportale und E-Commerce-Shops des Opfers während laufender Verhandlungen, um den Druck zu maximieren.
- **Harassment:** Automatisierte Telefonanrufe (Robocalls), SMS und gezielte E-Mails an Vorstandsmitglieder, Mitarbeiter, Kunden und Geschäftspartner des Opfers ("Wir haben eure Gehaltsdaten und Kundenkonten; zwingt euer Management zu zahlen, sonst veröffentlichen wir alles").

### Stufe 4: Regulatorische Erpressung (Quadruple Extortion)
- Angreifer drohen mit Selbstanzeige des Opfers bei Behörden:
  - Meldung an Datenschutzbehörden (DSGVO Art. 33/34: bis zu 20 Mio. Euro oder 4 % des weltweiten Jahresumsatzes).
  - Meldung an Finanzaufsichtsbehörden (SEC, BaFin, BaFin-Meldepflichten).
  - Im Fall ALPHV/BlackCat reichten die Angreifer im November 2023 selbstständig eine Whistleblower-Beschwerde bei der US-Börsenaufsicht SEC gegen das Opfer Meridian Energy ein, weil dieses den Vorfall nicht fristgerecht binnen 4 Tagen gemeldet hatte!

---

## 6. Resilienz und Abwehr (Gegenprobe)

### Schutz gegen S3 SSE-C & Cloud-Ransomware
1. **S3 Object Lock (Compliance Mode / WORM):**
   - Im Compliance-Modus kann eine gespeicherte Objektversion von **niemandem** (auch nicht vom AWS Root-Account) vor Ablauf der definierten Aufbewahrungsfrist überschrieben oder gelöscht werden.
2. **AWS Backup Vault Lock:**
   - Verhindert das vorzeitige Löschen von Backups und das Verringern der Aufbewahrungsfristen durch kompromittierte Administratorkonten.
3. **IAM- und SCP-Restriktionen:**
   - Service Control Policy (SCP) auf AWS-Organizations-Ebene verbietet das Überschreiben mit SSE-C:
     ```json
     {
       "Effect": "Deny",
       "Action": "s3:PutObject",
       "Resource": "*",
       "Condition": {
         "Null": { "s3:x-amz-server-side-encryption-customer-algorithm": "false" }
       }
     }
     ```
   - Verbot von `cloudtrail:StopLogging` und `kms:ScheduleKeyDeletion` über SCP.
4. **Azure Key Vault Purge Protection aktivieren:**
   - Verhindert das sofortige Bereinigen gelöschter Schlüssel während der Soft-Delete-Aufbewahrungszeit.

---

## Quellen

- Rhino Security Labs: S3 Ransomware – Part 1: Attack Vector Using SSE-C (2023/2024).
- CISA & FBI Cybersecurity Advisory: Threat Actors Use Legitimate Cloud Services for Exfiltration and Extortion.
- AWS Security Documentation: Protecting Data Using Server-Side Encryption with Customer-Provided Keys (SSE-C).
- Sophos: The Evolution of Cloud-Targeting Extortion Campaigns (2025).
- Coveware / BSI: Quartalsberichte zu Mehrfach-Erpressung und Datenleaks.
