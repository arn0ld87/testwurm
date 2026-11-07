# Ransomware – Band 15: Linux- und ESXi-Implementierungspfad (POSIX-Mechanik)

Programmiertechnischer Band: POSIX-I/O-Primitives, VMFS-Locks, Hypervisor-Shutdown und Anti-Forensik. Quellen am Ende.

## 1. Architektur-Voraussetzungen: Linux vs. VMware ESXi

Während die Bände 08 bis 10 die Windows-API behandeln, dominieren im Unternehmenskontext Linux- und Hypervisor-Ziele den Schadenshebel. Ein kompromittierter VMware ESXi-Server erlaubt es Angreifern, mit einem einzigen Implantat-Lauf die virtuellen Festplatten von Dutzenden oder Hunderten Gast-Systemen (Domain Controller, Datenbanken, ERP-Systeme) simultan zu verschlüsseln.

### Die ESXi-Sonderlage
VMware ESXi ist **kein Standard-Linux**. Zwar ähnelt das interaktive Userland über die SSH-Konsole einer Linux-Shell, der Kern ist jedoch der proprietäre **VMkernel**:
- **Keine Standard-Glibc:** Das Userland stützt sich auf eine abgespeckte BusyBox-Umgebung mit eigener System-C-Bibliothek.
- **Kein Paketmanager / Interpreter:** Weder Python, Perl noch ein GCC-Compiler sind verlässlich vorhanden.
- **Build-Anforderung:** Ein portabler Encoder für ESXi muss als **statisches 64-Bit-ELF-Binärformat** kompiliert werden (z. B. via C/C++ mit musl-libc oder als statisches Rust-Target `x86_64-unknown-linux-musl` bzw. Go mit `CGO_ENABLED=0`).
- **Initial Access:** Erfolgt typischerweise über vCenter-Schwachstellen (z. B. Remote Code Execution in vCenter Server), kompromittierte vSphere-Administrator-Anmeldedaten oder laterale Bewegung aus dem Active Directory, gefolgt von der Aktivierung des SSH-Dienstes (`vim-cmd hostsvc/enable_ssh`).

---

## 2. VM-Discovery und kontrollierter Hypervisor-Shutdown

Bevor eine virtuelle Festplatte auf dem Dateisystem verändert werden kann, **muss** die zugehörige virtuelle Maschine heruntergefahren oder ihr Prozess terminiert werden. Andernfalls hält der VMkernel exklusive Locks auf den VMFS-Dateien.

### Enumeration und Shutdown-Sequenz via VMkernel-CLI

```
1. VMs enumerieren:
   vim-cmd vmsvc/getallvms
   → Ausgabe parsen: Vmid, Name, File-Pfad (.vmx), Guest-OS

2. Sanfter Shutdown-Versuch (Guest-Shutdown):
   vim-cmd vmsvc/power.shutdown <Vmid>

3. Erzwungener Power-Off (nach Timeout oder direkt):
   vim-cmd vmsvc/power.off <Vmid>

4. Prozessprüfung auf World-Ebene:
   esxcli vm process list
   → Falls VM hängt: esxcli vm process kill --type=force --world-id=<WorldID>
```

### VMFS-Lock-Mechanik (.lck-Dateien und VAAI)
VMFS verwendet verteilte Sperren (Distributed Locking / Atomic Test and Set ATS), um gleichzeitige Schreibzugriffe mehrerer Hosts auf ein SAN/NAS LUN zu koordinieren.
- Solange der `vmx`-Prozess der VM läuft, ist die Datei `-flat.vmdk` gesperrt. Jeder Schreibversuch via `open(..., O_RDWR)` schlägt mit `EBUSY` oder `EACCES` fehl.
- Reale Implantate (Babuk, LockBit Linux, Akira) iterieren nach dem `power.off`-Kommando durch `/vmfs/volumes/` und prüfen, ob Prozesse noch offene Handles halten (`fuser` / `/proc`-Inspektion). Hängende Prozesse werden mit `kill -9` beendet.

---

## 3. VMFS-Struktur und File Targeting

Auf einem ESXi-Datenspeicher (`/vmfs/volumes/<Datastore-UUID>/<VM-Name>/`) existieren mehrere Dateitypen mit unterschiedlicher Schadenswirkung:

| Dateiendung | Funktion | Targeting-Strategie |
|---|---|---|
| `.vmdk` | Kleiner Text-Deskriptor (wenige KB) | Sofortige Verschlüsselung / Löschung bricht vSphere-Boot sofort. |
| `-flat.vmdk` | Tatsächlicher Raw-Blockcontainer (GB bis TB) | Primäres Ziel: Enthält das Gast-Dateisystem. Partiell verschlüsseln! |
| `.vmx` / `.vmxf` | Konfigurationsdatei der VM | Verschlüsseln; verhindert Neuregistrierung ohne Backup. |
| `.vmsn` / `.vmdk.delta` | Snapshot-Metadaten und Delta-Disks | Zwingend verschlüsseln, um Snapshot-Rollbacks zu unterbinden. |
| `.nvram` | BIOS/UEFI-Zustand | Mitverschlüsseln oder löschen. |

### Die -flat.vmdk-Problematik: Voll- vs. Partial Encryption
Eine virtuelle Festplatte umfasst oft 500 GB bis 10 TB. Eine vollständige Verschlüsselung würde:
1. Stunden bis Tage pro Host beanspruchen.
2. Massive Storage-I/O-Alarme im SAN/vCenter auslösen.
3. Den lokalen Flash-Storage des ESXi-Hosts überlasten.

**Lösung moderner Implantate (z. B. Babuk/Akira ESXi-Zweig):**
- **Header-Encryption:** Die ersten 10 bis 100 MB der `-flat.vmdk` werden verschlüsselt. Dies zerstört Partitionstabellen (MBR/GPT), Dateisystem-Superblocks (EXT4/XFS) oder NTFS-Bootsektoren irreversibel.
- **Interleaved/Strided Encryption:** Abwechselnd Blöcke verschlüsseln und überspringen (z. B. 1 MB verschlüsseln, 9 MB skippen). Das macht ein Recovery von Datenbankseiten (MDF, InnoDB, Postgres) mathematisch unmöglich, reduziert die Schreiblast aber um 90 %.

---

## 4. Low-Level POSIX-I/O-Mechanik

Unter Linux/POSIX erfordert maximale Verschlüsselungsgeschwindigkeit eine präzise Handhabung von Kernel-Puffern und Systemaufrufen.

### Die Flags von `open()`
Für In-Place-Modifikation großer Dateien:

```c
int fd = open(filepath, O_RDWR | O_DIRECT | O_NOATIME);
```

1. **`O_DIRECT`:**
   - Umgeht den Kernel Page Cache vollständig. Das I/O geht direkt vom Userland-Puffer auf das Blockgerät.
   - **Vorteil:** Verhindert, dass Terabytes an Lesedaten das System-RAM überfluten (Buffer Bloat), den OOM-Killer (Out of Memory) triggern oder das Host-Monitoring aufwecken.
   - **Bedingung:** Pufferadresse, Dateioffset und Transferlänge müssen exakt auf die Blockgröße des Dateisystems ausgerichtet sein (512 Bytes oder 4096 Bytes). Allokation via `posix_memalign(&buf, 4096, chunk_size)`.
2. **`O_NOATIME`:**
   - Aktualisiert nicht den Zugriffszeitstempel (`atime`) der Datei beim Lesen. Reduziert unnötige Metadaten-Schreiboperationen auf dem Storage.
3. **`posix_fadvise()` als Fallback:**
   - Schlägt `O_DIRECT` auf Netzwerk-Mounts (z. B. NFS-Datastores) fehl, öffnet das Implantat regulär und setzt:
     ```c
     posix_fadvise(fd, 0, 0, POSIX_FADV_DONTNEED);
     ```
   - Dies weist den Linux-Kernel an, gelesene Pages sofort aus dem Page Cache zu verwerfen.

### In-Place Mutation mit `pwrite64()`
Verschlüsselung im POSIX-Umfeld erfolgt atomar an Dateipositionen:
```c
ssize_t bytes_written = pwrite64(fd, encrypted_chunk, chunk_size, offset);
```
- `pwrite64()` liest/schreibt an explizitem Offset ohne Modifikation des Dateideskriptor-Pointers.
- Dies erlaubt echten Multi-Threading-Betrieb: Mehrere Worker-Threads können gleichzeitig an disjunkten Offsets derselben großen VMDK schreiben, ohne `lseek()`-Race-Conditions.

### Asynchrones I/O: `io_uring` vs. Threads
- Ältere Linux-Malware nutzte `pthreads` mit synchronen blockierenden I/O-Calls.
- Moderne Linux-Implantate (ab Kernel 5.1+) setzen zunehmend auf `io_uring`:
  - Einreichung von Batches von Lese- und Schreiboperationen über Ringpuffer (`io_uring_sqe`) ohne Context-Switch-Overhead pro I/O-Operation.
  - Ermöglicht Sättigung von NVMe- und Flash-Storage mit wenigen Kernen.

---

## 5. Linux Process Hunting & Anti-Forensik

Auf Standard-Linux-Systemen (Ubuntu, RHEL, SLES) halten Datenbanken und Dienste Locks auf Nutzerdaten.

### Dienst- und Prozess-Terminierung
Reale Linux-Ransomware führt vor der Verschlüsselung Shell-Kommandos oder API-Loops aus:
- Datenbanken und Container stoppen:
  ```bash
  pkill -9 -f "mysqld|postgres|mongod|redis-server|oracle|docker|containerd|qemu"
  ```
- Freigabe offener Dateihandles:
  ```bash
  fuser -k -9 /var/lib/mysql /var/lib/postgresql /data
  ```

### Anti-Forensik und Log-Wiping
Um eine forensische Rekonstruktion der Einbruchszeitpunkte zu vereiteln:
1. **Linux Audit-Subsystem abschalten:**
   ```bash
   auditctl -e 0
   ```
2. **Systemd-Journale leeren:**
   ```bash
   journalctl --vacuum-time=1s
   ```
3. **Auth- und Shell-Historien löschen:**
   ```bash
   shred -u /var/log/audit/audit.log /var/log/auth.log /var/log/secure
   history -c && rm -f ~/.bash_history
   ```
4. **Log-Inodes mit Append-Only Flag behandeln:**
   - Manche gehärtete Linux-Systeme nutzen `chattr +a` auf Logs.
   - Angreifer rufen vor dem Löschen `chattr -ia /var/log/*` auf.

---

## 6. Reale Fallbeispiele & Codebasen

### Babuk ESXi (Leak 2021)
- Geschrieben in Standard-C, kompiliert mit GCC für Linux/ESXi.
- Krypto: Curve25519 (ECDH) für asymmetrischen Schlüssel-Handshake, Sosemanuk / ChaCha20 für symmetrische Datenverschlüsselung.
- Verwendet `posix_fadvise()` und POSIX-Threads (`pthread_create`), parst VM-Listen direkt aus `vim-cmd`.

### LockBit Linux/ESXi (2022–2024)
- Hochoptimierter ELF-Encoder.
- Unterstützt ESXi 7.x und 8.x.
- Konfigurierbare Partial-Encryption-Prozentsätze (1 % bis 100 %), prüft freie Sektoren vor dem Header-Write.

### ESXiArgs (Februar 2023)
- Globaler Massenangriff auf ungepatchte ESXi-Hosts (OpenSLP-Schwachstelle CVE-2021-21974).
- Kombination aus Shell-Skript (`encrypt.sh`) und kompilierter ELF-Schadsoftware.
- Verschlüsselte gezielt `.vmdk`, `.vmx`, `.vmxf`, `.vmsd` und Metadaten, ließ jedoch `-flat.vmdk` teils unangetastet, was vielen Opfern eine Rekonstruktion über vmdk-Header-Neuerstellung erlaubte (Designfehler der Angreifer).

---

## 7. Detektion und Abwehr (Gegenprobe)

### eBPF-basierte Verhaltensüberwachung
Traditionelle Linux-Virenscanner sind auf Hypervisoren und Hochleistungsservern oft nicht installierbar oder blind für schnelle In-Place-Schreibvorgänge.
- **eBPF (Tetragon, Tracee):** Hookt auf Syscall-Ebene (`sys_enter_openat`, `sys_enter_pwrite64`).
- **Detektionsanker:**
  1. Prozess ruft `openat()` mit `O_DIRECT` auf Dateien mit Endung `.vmdk` auf, ist aber kein legitimer `vmx`- oder Storage-Worker-Prozess.
  2. Massenhafter Aufruf von `pwrite64` auf Header-Regionen von Blockdateien innerhalb kurzer Zeitfenster.
  3. Ausführung von `vim-cmd vmsvc/power.off` oder `esxcli vm process kill` außerhalb regulärer Wartungsfenster.

### ESXi-Härtungsempfehlungen
1. **Lockdown Mode (Strict):** Verhindert jeden direkten Host-Zugriff via SSH; Verwaltung ausschließlich über vCenter.
2. **SSH-Dienst deaktivieren:** SSH auf ESXi-Hosts muss per Default beendet sein und darf nur für Ad-hoc-Wartungen gestartet werden.
3. **Dedicated Management Network:** vSphere Management Network strikt von Gast-Netzen und dem Internet isolieren (keine Public IP für ESXi/vCenter!).
4. **Out-of-Band Immutable Storage Snapshots:** SAN/NAS-Speichersysteme (z. B. ZFS Snapshots, NetApp Snapshot Copies) müssen mit WORM/Immutable-Sperren konfiguriert sein, die nicht über die ESXi-Management-Schnittstelle gelöscht werden können.

---

## Quellen

- Huntress: Hypervisor Defenses Against Ransomware Targeting ESXi (2025).
- VMware Security Advisory: VMSA-2023-0023, VMSA-2024-0019 (vCenter RCE).
- CERT-FR: Alert on ESXiArgs Ransomware Campaign (02/2023).
- Babuk Ransomware Source Code Leak (ESXi Module Analysis, 2021).
- Linux Programmer's Manual: `open(2)`, `pwrite(2)`, `posix_fadvise(2)`, `io_uring(7)`.
