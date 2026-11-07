# Ransomware – Band 22: OT-, ICS- und SCADA-Targeting in Kritischen Infrastrukturen

Technischer Deep Dive: Purdue-Modell-Traversierung, OT-spezifische Ransomware-Mechaniken (EKANS/Snake), Industrie-Dienst-Kill-Listen, Protokoll-Missbrauch (Modbus/TCP, S7comm, CIP) und IEC 62443 Härtungsarchitektur.

---

## 1. Architektur industrieller Steuerungsumgebungen (ICS/SCADA)

In industriellen Umgebungen (Energie, Wasser, Chemie, Pharma, Fertigung) steuern Operational Technology (OT) Systeme physikalische Anlagen. Im Gegensatz zur klassischen Unternehmens-IT gilt hier die fundamentale Priorität **Safety & Availability > Integrity > Confidentiality**.

```
+----------------------------------------------------------------------------+
| Das Purdue-Modell (ISA-95) und Traversierungspfade                        |
+----------------------------------------------------------------------------+
| Level 4/5: Enterprise IT (Active Directory, ERP, Mail, Workstations)       |
|            |                                                               |
|            v [ Angriffsvektor: Phishing / Exploit / C2 Beacon ]            |
| +------------------------------------------------------------------------+ |
| | Level 3.5: Industrial DMZ (IT/OT Schnittstelle)                        | |
| |   - Jump Hosts / Bastion Hosts (RDP / SSH)                             | |
| |   - Historian Mirror / Patch-Management / AV-Server                    | |
| +------------------------------------------------------------------------+ |
|            |                                                               |
|            v [ Laterale Bewegung: Gekaperte Jump-Host Credentials ]        |
| +------------------------------------------------------------------------+ |
| | Level 3: Site Operations (OT-Management)                               | |
| |   - SCADA Core Server, Engineering Workstations (EWS)                  | |
| |   - Prozess-Historian (OSIsoft PI), Backup-Systeme                     | |
| +------------------------------------------------------------------------+ |
|            |                                                               |
|            v [ Industrieprotokolle: Modbus, S7comm, CIP, OPC-UA ]          |
| +------------------------------------------------------------------------+ |
| | Level 2: Supervisory Control (HMI / Bedienstationen)                    | |
| |   - Human-Machine Interfaces (Siemens WinCC, Wonderware, FactoryTalk)   | |
| +------------------------------------------------------------------------+ |
|            |                                                               |
|            v [ Steuerbefehle / Feldbus ]                                   |
| +------------------------------------------------------------------------+ |
| | Level 1: Basic Control (SPS / PLC / RTU / Safety Systems)              | |
| |   - Speicherprogrammierbare Steuerungen (Siemens S7, Allen-Bradley)     | |
| |   - Safety Instrumented Systems (SIS: Triconex, HIMA)                   | |
| +------------------------------------------------------------------------+ |
|            |                                                               |
|            v [ I/O Signale 4-20mA, Relais, Ventile ]                       |
| +------------------------------------------------------------------------+ |
| | Level 0: Physischer Prozess (Motoren, Pumpen, Sensoren, Reaktoren)      | |
+----------------------------------------------------------------------------+
```

### 1.1 Typische Traversierungspfade von IT zu OT

Angreifer gelangen selten direkt ins OT-Netzwerk. Typische Einbruchspfade:
1. **Dual-Homed Workstations:** Ingenieurs-Laptops oder Workstations mit Netzwerkkarten in beiden Netzen (IT und OT).
2. **Kollabierte Industrial DMZ:** Direkte Freigaben von IT-zu-OT für RDP (Port 3389) oder SMB (Port 445), oft zur Fernwartung eingerichtet.
3. **Gemeinsames Active Directory:** Die OT-Domain vertraut der kompromittierten IT-Domain (Transitive Forest Trust), wodurch Domain-Admin-Credentials aus der IT direkt auf OT-Historians und HMIs administrative Rechte besitzen.

---

## 2. OT-spezifische Ransomware (EKANS / Snake Analyse)

Historische Ransomware (z. B. WannaCry, NotPetya) traf industrielle Netze meist als Kollateralschaden über SMB. Ab 2020 entwickelten Akteure spezialisierte Malware, die gezielt industrielle Software identifiziert und stoppt.

### 2.1 Anatomie von EKANS (Snake)

EKANS (bekannt geworden durch Angriffe auf Honda und Fresenius) enthält eine fest einprogrammierte Liste von Dienst- und Prozessnamen aus der industriellen Automation:

```
+-----------------------------------------------------------------------+
| EKANS Prozess- und Dienst-Targeting                                   |
+-----------------------------------------------------------------------+
| 1. Enumeration aller laufenden Prozesse (CreateToolhelp32Snapshot)     |
| 2. String-Vergleich gegen fest einprogrammierte Industrie-Blacklist   |
| 3. Erzwingen der Dienstbeendigung (OpenSCManager / ControlService)    |
| 4. Terminierung der Prozess-Handles (TerminateProcess)                |
| 5. Beginn der Dateiverschlüsselung                                    |
+-----------------------------------------------------------------------+
```

#### Auszug aus der realen EKANS-Targeting-Liste:
```c
// Typische Prozessziele von EKANS zur Zerstörung der Anlagenüberwachung:
const char* g_IcsTargets[] = {
    "geesebc.exe",       // GE Fanuc VersaMax SPS-Kommunikation
    "pcedcom.exe",       // Proficy Historian Datensammler
    "proficy.exe",       // GE Proficy HMI/SCADA Software
    "hilscher.exe",      // Hilscher Feldbus-Treiber und Gateways
    "fservice.exe",      // FactoryTalk View Dienst (Rockwell Automation)
    "viewservice.exe",   // FactoryTalk View SE Service
    "rslinx.exe",        // Rockwell Automation RSLinx Kommunikationsserver
    "hartcomm.exe",      // HART-Protokoll Kommunikationsdienste
    "scadasvr.exe",      // SCADA Engine Prozess
    "licman.exe",        // Siemens Lizenzmanager (stoppt HMI-Lizenzen)
    NULL
};
```

#### Auswirkung des gezielten Dienst-Stopps:
- **Blindheit der Operatoren:** Wenn `proficy.exe` oder `viewservice.exe` beendet wird, frieren die Bildschirme im Kontrollraum ein. Operatoren sehen Druck- und Temperaturwerte nicht mehr.
- **Freigabe von Datenbankdateien:** Prozess-Historians (z. B. OSIsoft PI, Wonderware InSQL) halten ihre `.mdf`-, `.ldf`- und Time-Series-Archive exklusiv gesperrt. Das Beenden der Dienste entlastet die Handles und ermöglicht der Ransomware, die gesamten historischen Prozessdaten zu verschlüsseln.

---

## 3. Industrieprotokolle und ihre Verwundbarkeit

Level 1 Steuerungen (SPS / PLC) nutzen Legacy-Protokolle, die vor Jahrzehnten ohne Sicherheitsmechanismen (keine Authentifizierung, keine Verschlüsselung, kein Replay-Schutz) entworfen wurden.

### 3.1 Modbus/TCP (Port 502)

Modbus/TCP transportiert Steuerbefehle über unverschlüsseltes TCP/IP. Jedes System im Netzwerk kann ohne Passwort Lese- und Schreibbefehle absetzen.

#### Relevante Function Codes für Manipulationen:
| Function Code | Name | Auswirkung im Angriffsszenario |
|---|---|---|
| **0x01 (Read Coils)** | Diskrete Ausgänge lesen | Status von Relais, Ventilen und Pumpen ausspähen |
| **0x03 (Read Holding Registers)** | Halteregister lesen | Grenzwerte, Soll-Temperaturen und Drehzahlen auslesen |
| **0x05 (Write Single Coil)** | Einzelnen Ausgang setzen | Pumpe oder Notfallventil gezielt ein- oder ausschalten |
| **0x06 (Write Single Register)** | Einzelnes Register schreiben | Sollwert manipulieren (z. B. Druckgrenze von 5 auf 50 Bar erhöhen) |
| **0x0F (Write Multiple Coils)** | Mehrere Ausgänge setzen | Komplette Abschaltung ganzer Anlagensegmente erzwingen |
| **0x10 (Write Multiple Registers)**| Mehrere Register schreiben | Parametrierung der SPS überschreiben |

#### Paketaufbau Modbus/TCP (MBAP Header + PDU):
```
[ Transaction ID: 2 Bytes ] [ Protocol ID: 2 Bytes (0x0000) ]
[ Length: 2 Bytes ]         [ Unit ID: 1 Byte ]
[ Function Code: 1 Byte ]   [ Data Payload: n Bytes ]
```

### 3.2 Siemens S7comm (Port 102 / ISO-on-TCP)

S7comm (für S7-300 / S7-400) und S7comm-plus (S7-1200 / S7-1500) steuern Siemens-SPS-Systeme.
- Über Port 102 können Befehle wie `CPU Start` und `CPU Stop` übertragen werden.
- **SPS-Freeze:** Ein `CPU Stop`-Befehl versetzt die Steuerung in den Halt-Zustand. Die Anlage stoppt abrupt, was in der Prozessindustrie (z. B. flüssiger Stahl, chemische Reaktionen) innerhalb von Minuten Millionenschäden verursacht.

### 3.3 Ethernet/IP & CIP (Common Industrial Protocol, Port 44818)

Standard in Rockwell / Allen-Bradley Umgebungen:
- Unterstützt "Explicit Messaging" und "Implicit I/O Messaging".
- Bietet Services zum Überschreiben der Firmware oder zum Löschen des PLC-Programmspeichers (`Reset Service`).

---

## 4. Safety Instrumented Systems (SIS) Manipulation

In kritischen Chemie- und Kraftwerksanlagen existiert neben der Basisautomatisierung (BPCS) ein unabhängiges Sicherheitssystem (Safety Instrumented System, Level 1b).
- **Aufgabe:** Wenn Druck oder Temperatur lebensbedrohliche Niveaus erreichen, schließt das SIS automatisch Ventile und fährt die Anlage in den sicheren Zustand.
- **Angriffsmuster (TRITON / TRISIS):** Angreifer schleusen über kompromittierte Engineering Workstations modifizierte Logik auf Safety-Controller (z. B. Schneider Electric Triconex). Wird die Sicherheitslogik deaktiviert, führt eine nachfolgende Ransomware-Verschlüsselung der HMI nicht nur zu Betriebsstillstand, sondern zu physischen Explosions- oder Vergiftungsgefahren.

---

## 5. Härtungsarchitektur nach IEC 62443

Um OT-Systeme effektiv vor Ransomware zu schützen, definiert die Normenreihe **ISA/IEC 62443** spezifische Sicherheitsanforderungen.

```
+-----------------------------------------------------------------------+
| IEC 62443 Zonen- und Conduit-Schutzkonzept                            |
+-----------------------------------------------------------------------+
| Zone A: Enterprise IT          Conduit (NGFW / ZTNA)                  |
| [ ERP / Exchange / AD ] <===========================> [ DMZ Gateway ] |
|                                                              |        |
| Zone B: Operations (Level 3)   Conduit (DPI Firewall)        |        |
| [ SCADA Core / Historian ] <=================================+        |
|             |                                                         |
|             v Conduit (Streng unidirektional via Daten-Diode)         |
| [ Historian Mirror in DMZ ]                                           |
|                                                                       |
| Zone C: Cell / Basic Control (Level 1/2)                              |
| [ SPS / PLCs / HMIs ]                                                 |
| - Nur dedizierte Conduits für Modbus/S7comm                           |
| - DPI: Erlaubt nur READ-Funktionen, blockiert WRITE-Codes             |
+-----------------------------------------------------------------------+
```

### 5.1 Kernmaßnahmen zur Härtung

1. **Strikte Zonen und Conduits:** Kein ungefilterter Durchgriff von IT in OT. Jeder Übergang muss durch ein Conduit (Firewall, Proxy) reglementiert sein.
2. **Unidirektionale Daten-Dioden:** Datenübertragung von OT-Historians in die IT-Welt darf nur physikalisch unidirektional (Lichtwellenleiter ohne Rückkanal) erfolgen.
3. **Deep Packet Inspection (DPI) für Industrieprotokolle:**
   - Firewalls zwischen Level 2 und Level 1 müssen Modbus/S7-Pakete dekodieren.
   - **Regel:** HMIs dürfen nur Function Code `0x03` (Read Holding Registers) senden; Schreibbefehle (`0x06`, `0x10`) sind auf autorisierte Engineering Workstations während Wartungsfenstern zu beschränken.
4. **Isoliertes Active Directory:** Kein Vertrauensverhältnis (Trust) zwischen IT- und OT-Forests. Eigene Zertifikatsdienste (PKI) und Multi-Faktor-Authentifizierung (MFA) für alle Jump-Host-Zugriffe.

---

## Quellen
- [Q1] CyberDefenders – History of Ransomware: From Floppy Disk to RaaS
- [Q73] CISA – Alert AA20-106A: Ransomware Targeting Industrial Control Systems (EKANS / Snake)
- [Q74] Dragos – Industrial Control Systems Cyber Security Year in Review 2024/2025
- [Q75] ISA/IEC 62443 Series – Security for Industrial Automation and Control Systems
- [Q76] Mandiant – Attackers Innovating in the OT Space: From IT Intrusion to Physical Disruption
