# Ransomware – Band 20: EDR-Hook-Evasion und Loader-Architektur

Technischer Deep Dive: User-Mode Hooking in `ntdll.dll`, Syscall-Evolution (Hell's Gate, Halo's Gate, Indirect Syscalls), Call Stack Spoofing, AMSI/ETW-Blinding, In-Memory PE Loading und EDR-Detection-Engineering.

---

## 1. User-Mode Hooking Mechanik in ntdll.dll

Endpoint Detection and Response (EDR) Systeme (z. B. CrowdStrike Falcon, SentinelOne, Microsoft Defender for Endpoint) basieren architektonisch auf zwei Säulen: einem Kernel-Treiber (Ring 0) und einer User-Mode Überwachungs-DLL (Ring 3), die in jeden neu erzeugten Prozess injiziert wird.

```
+-------------------------------------------------------------------------+
| User-Mode (Ring 3) - Anwendungs- oder Schadprozess                     |
|                                                                         |
|  [ Eigener Code / Loader ]                                              |
|            |                                                            |
|            v (Aufruf z. B. VirtualAlloc / NtAllocateVirtualMemory)       |
|  [ ntdll.dll Stubs ]                                                    |
|    +-----------------------------------------------------------------+  |
|    | NtAllocateVirtualMemory:                                        |  |
|    |   [ EDR Inline Hook: JMP 0x... ] --------+                      |  |
|    |   mov r10, rcx                           |                      |  |
|    |   mov eax, <SSN>                         |                      |  |
|    |   syscall                                |                      |  |
|    |   ret                                    |                      |  |
|    +------------------------------------------|----------------------+  |
|                                               v                         |
|                                      [ EDR User-Mode Engine ]           |
|                                        - Prüft Parameter                |
|                                        - Inspiziert Call Stack          |
|                                        - Prüft Memory Permissions       |
|                                               |                         |
|            +----------------------------------+                         |
|            v (Entweder Block/Alert oder Rücksprung)                     |
+------------|------------------------------------------------------------+
| Kernel     v (syscall Transition via Ring 0)                            |
| +---------------------------------------------------------------------+ |
| | SSDT (System Service Descriptor Table) -> nt!NtAllocateVirtualMemory| |
| +---------------------------------------------------------------------+ |
+-------------------------------------------------------------------------+
```

### 1.1 Aufbau legitimer Syscall-Stubs in x64 Windows

In der 64-Bit-Version von Windows stellt `ntdll.dll` die unterste Schicht der Win32-Subsystem-Architektur dar. Hier befinden sich die systemnahen Wrapper, die den Übergang vom User-Mode (Ring 3) in den Kernel-Mode (Ring 0) vollziehen. Ein unmodifizierter Syscall-Stub besitzt unter modernen Windows 10/11 und Windows Server Builds folgendes Assembler-Layout:

```assembly
; Prototypischer x64 ntdll.dll Syscall-Stub
ntdll!NtAllocateVirtualMemory:
    mov r10, rcx            ; 4C 8B D1       - Kopiert erstes Argument nach R10 (Kernel-Konvention)
    mov eax, 0x0018         ; B8 18 00 00 00 - Lädt die System Service Number (SSN) in EAX
    test byte ptr [7FFE0308h], 1 ; F6 04 25 08 03 FE 7F 01 - Testet KUSER_SHARED_DATA (Fast Syscall)
    jne ntdll!NtAllocateVirtualMemory+0x15 ; 75 03
    syscall                 ; 0F 05          - Ring-0 Transition (Kernel Eintritt)
    ret                     ; C3             - Rücksprung zum Aufrufer
```

Die System Service Number (SSN, hier `0x18`) identifiziert die gewünschte Kernel-Funktion im System Service Descriptor Table (SSDT). Die SSN variiert zwischen Windows-Releases, Build-Versionen und Service-Packs.

### 1.2 Mechanik des Inline-Hookings

Um API-Aufrufe abzufangen, modifiziert der EDR-Agent kurz nach der Prozesserzeugung den Speicher von `ntdll.dll`. Der Agent nutzt `VirtualProtect`, um die Sektion `.text` temporär beschreibbar zu machen (`PAGE_EXECUTE_READWRITE`), überschreibt die ersten Bytes des Stubs und setzt die Rechte zurück:

1. **5-Byte Relativer Sprung (Opcode `0xE9`):**
   ```assembly
   jmp relative_offset      ; E9 xx xx xx xx
   ```
   Erfordert, dass der EDR-Hook-Handler innerhalb eines 2-GB-Fensters (+/- 0x7FFFFFFF Bytes) im Adressraum liegt.
2. **14-Byte Absoluter Sprung (Opcode `0xFF 0x25`):**
   ```assembly
   jmp qword ptr [rip + 0]  ; FF 25 00 00 00 00
   dq 0x00007FFB12345678    ; 8-Byte 64-Bit absolute Zieladresse
   ```
   Ermöglicht den Sprung an beliebige 64-Bit-Speicheradressen, überschreibt jedoch mehr Befehlszeilen des Originalstubs.

### 1.3 Was die EDR-Hook-Engine inspiziert

Wenn die Programmausführung in den Hook-Handler umgeleitet wird, führt der EDR tiefgehende Heuristiken aus:
- **Speicherberechtigungen:** Aufrufe von `NtProtectVirtualMemory` oder `NtAllocateVirtualMemory` mit `PAGE_EXECUTE_READWRITE` (RWX) lösen sofortige Verdachtsmomente aus.
- **Aufrufer-Adresse:** Zeigt die Rücksprungadresse auf ungesicherten ("unbacked"), privaten Speicher (nicht aus einer geladenen DLL auf Festplatte stammend), wird die Ausführung als verdächtig eingestuft.
- **Argument-Plausibilität:** Werden verdächtige Zielprozesse (`lsass.exe`, `explorer.exe`) geöffnet (`NtOpenProcess` mit `PROCESS_ALL_ACCESS` oder `PROCESS_VM_READ`)?
- **Call-Stack-Analyse:** Der EDR traversiert den Stack (RtlVirtualUnwind), um zu verifizieren, ob der Aufruf aus einer plausiblen Win32-Kette (z. B. `kernel32!VirtualAlloc` -> `KernelBase!VirtualAllocEx` -> `ntdll!NtAllocateVirtualMemory`) stammt.

---

## 2. Evolution der Syscall-Techniken

Angreifer und Red-Team-Entwickler entwickelten daraufhin Methoden, um die Hooks in `ntdll.dll` vollständig zu umgehen.

### 2.1 Direct Syscalls: Hell's Gate, Halo's Gate und Tartarus' Gate

Beim Direct Syscall führt der eigene Schadcode die Instruktionen `mov r10, rcx`, `mov eax, SSN` und `syscall` direkt im eigenen Speicherbereich aus, ohne `ntdll.dll` aufzurufen.

#### Hell's Gate (Dynamische SSN-Ermittlung)
Hell's Gate parst zur Laufzeit den Process Environment Block (PEB), lokalisiert die Basisadresse von `ntdll.dll` und traversiert die Export Address Table (EAT):
1. Ermitteln des Hashes der Zielfunktion (z. B. `NtAllocateVirtualMemory`).
2. Suchen der RVA im Export Directory.
3. Lesen der ersten 4 Bytes des Ziel-Stubs im Speicher.
4. Prüfen, ob die Sequenz unmodifiziert ist:
   ```c
   // Hell's Gate Prüfmuster:
   // 4C 8B D1          -> mov r10, rcx
   // B8 <SSN_LOW> <SSN_HIGH> 00 00 -> mov eax, SSN
   if (*(PBYTE)pFunctionAddress == 0x4C &&
       *((PBYTE)pFunctionAddress + 1) == 0x8B &&
       *((PBYTE)pFunctionAddress + 2) == 0xD1 &&
       *((PBYTE)pFunctionAddress + 3) == 0xB8) {
       WORD ssn = *(PWORD)((PBYTE)pFunctionAddress + 4);
       return ssn;
   }
   ```
Ist der Stub intakt, wird die SSN direkt übernommen.

#### Halo's Gate (Umgang mit gehockten Stubs)
Ist der Stub durch einen EDR gehockt (beginnt mit `0xE9` oder `0xFF 0x25`), scheitert Hell's Gate. Halo's Gate nutzt eine fundamentale Windows-Eigenschaft: **In ntdll.dll sind Syscall-Stubs streng nach Funktionsnamen alphabetisch sortiert und weisen fortlaufende SSNs auf.**
- Halo's Gate sucht sequentiell 32 Bytes nach oben und 32 Bytes nach unten (benachbarte Stubs).
- Findet es einen unberührten Nachbar-Stub mit der SSN $S$ bei einem Offset von $N$ Stubs, berechnet es die gesuchte SSN als:
  $$\text{SSN}_{\text{Ziel}} = S \pm N$$

#### Das fundamentale Erkennungsproblem von Direct Syscalls
Moderne EDRs erkennen Direct Syscalls mit hoher Zuverlässigkeit:
- Bei jedem `syscall`-Befehl speichert die CPU den aktuellen Instruction Pointer (`RIP`) im Register `RCX` und wechselt in den Kernel.
- Kernel-Treiber (oder ETW-TI) prüfen den auslösenden `RIP`.
- **Regel:** Liegt `RIP` außerhalb der Adressgrenzen der legitimen `ntdll.dll` (z. B. in einer privaten Heap- oder Stack-Region), wird die Ausführung als manipulativer Syscall klassifiziert.

### 2.2 Indirect Syscalls

Indirect Syscalls lösen das `RIP`-Erkennungsproblem, indem sie die Ausführung des `syscall`-Opcodes zurück in den Speicher von `ntdll.dll` delegieren.

#### Architektur und Kontrollfluss
1. Der Schadcode lädt die Parameter und die SSN im eigenen Speicher:
   ```assembly
   ; Assembly-Stub für Indirect Syscall
   .code
   SyscallStub PROC
       mov r10, rcx                       ; Erstes Argument in R10
       mov eax, [g_SyscallNumber]         ; SSN in EAX laden
       jmp qword ptr [g_SyscallGadgetAddress] ; Sprung zu legitimer 'syscall; ret'-Sequenz
   SyscallStub ENDP
   END
   ```
2. `g_SyscallGadgetAddress` verweist auf eine beliebige legale Bytefolge `0F 05 C3` (`syscall; ret`) innerhalb von `ntdll.dll`.
3. Der Übergang in Ring 0 erfolgt nun mit einem `RIP`, der **innerhalb der legitimen ntdll.dll** liegt.

---

## 3. Synthetic Call Stack Spoofing

Auch bei Indirect Syscalls bleibt eine Achillesferse: der **Return Address Stack**. EDRs analysieren den Call Stack beim Eintreffen verdächtiger Operationen via Kernel-ETW-TI (`Microsoft-Windows-Threat-Intelligence`) oder asynchronen Thread-Scans.

### 3.1 Anatomie eines ungeschützten Call Stacks

Erfolgt ein Indirect Syscall naiv, sieht der Stack für den Kernel wie folgt aus:

```
Frame 0: ntdll.dll!NtAllocateVirtualMemory+0x14 (syscall; ret)
Frame 1: 0x000001D4A5201040 [Unbacked / Private Memory Region] <-- ALARM!
```
Es existiert keine logische Kette zu `kernel32.dll` oder dem Thread-Einsprungpunkt (`RtlUserThreadStart`).

### 3.2 Synthetische Stack-Rekonstruktion

Synthetic Stack Spoofing (z. B. SilentMoonwalk-Framework) manipuliert den Stack Pointer (`RSP`) und baut gefälschte Stack-Frames nach x64-ABI-Spezifikation auf:

1. **Stack Unwinding Konformität:** Jeder Frame muss über korrekte UNWIND_INFO-Einträge in der PE-Exception-Tabelle (`.pdata`) verfügen, damit `RtlVirtualUnwind` den Stack fehlerfrei ablaufen kann.
2. **Kombination mit ROP-Gadgets:** Vor dem Aufruf wird die legitime Rücksprungadresse auf ein `jmp rbx`- oder `ret`-Gadget in `kernelbase.dll` gelegt.
3. **Ergebnis der Manipulation:**
   ```
   Frame 0: ntdll.dll!NtAllocateVirtualMemory+0x14
   Frame 1: KERNELBASE.dll!VirtualAllocEx+0x42
   Frame 2: KERNEL32.dll!VirtualAlloc+0x18
   Frame 3: Programm.exe!main+0x105
   Frame 4: KERNEL32.dll!BaseThreadInitThunk+0x14
   Frame 5: ntdll.dll!RtlUserThreadStart+0x21
   ```
   Für den EDR und Kernel-Telemetry-Mechanismen ist dieser Call Stack syntaktisch und semantisch nicht von einem legitimen Systemaufruf unterscheidbar.

---

## 4. AMSI und ETW Patching & Blinding

Bevor Schadcode ausgeführt oder Skripte geladen werden, setzen Angreifer auf das Deaktivieren von Überwachungsschnittstellen im User-Mode.

### 4.1 AMSI-Bypass (AmsiScanBuffer Patching)

Das Antimalware Scan Interface (AMSI) überwacht Skriptausführungen (PowerShell, VBScript, .NET, JScript). Die Kernfunktion `amsi!AmsiScanBuffer` analysiert Puffer auf Signaturen.

```c
// Typische Signatur von AmsiScanBuffer in amsi.dll:
HRESULT AmsiScanBuffer(
    HAMSICONTEXT amsiContext,
    PVOID        buffer,
    ULONG        length,
    LPCWSTR      contentName,
    HAMSISESSION amsiSession,
    AMSI_RESULT  *result
);
```

#### Return-Code Patching
Wird die Funktion zu Beginn so gepatcht, dass sie sofort mit einem Fehlercode zurückkehrt, wird die Scan-Logik übersprungen und der Puffer als "sauber" (`AMSI_RESULT_CLEAN`) gewertet:

```assembly
; x64 Patch-Bytes für AmsiScanBuffer
mov eax, 0x80070057     ; B8 57 00 07 80 -> HRESULT E_INVALIDARG
ret                     ; C3
```

#### Hardware Breakpoint Patching (Vermeidung von VirtualProtect-Alarmen)
Das direkte Ändern von Speicherschutzrechten (`VirtualProtect` auf `PAGE_EXECUTE_READWRITE` in `amsi.dll`) löst bei EDRs sofortige Alarmmeldungen aus.
- **Hardware Breakpoints (Debug Register DR0–DR3):** Ein Angreifer registriert einen Vectored Exception Handler (VEH) und setzt über `SetThreadContext` einen Hardware-Breakpoint auf die Adresse von `AmsiScanBuffer`.
- Beim ersten Aufruf löst die CPU eine `STATUS_SINGLE_STEP`-Exception aus.
- Der VEH fängt die Exception ab, schreibt direkt das gewünschte Ergebnis (`AMSI_RESULT_CLEAN`) in den Rückgabeparameter `*result`, manipuliert den Instruction Pointer (`RIP`) auf den `ret`-Befehl und setzt die Ausführung fort – **vollständig ohne Speicherberechtigungsänderung**.

### 4.2 ETW Blinding (Event Tracing for Windows)

Über den Provider `Microsoft-Windows-Threat-Intelligence` und `Microsoft-Windows-Security-Mitigations` sendet `ntdll.dll` Telemetriedaten über Memory Allocations und Thread Injections.
- Die zentrale Emission erfolgt über `ntdll!EtwEventWrite`.
- **Patch:** Angreifer patchen die ersten Instruktionen von `EtwEventWrite` durch einen einfachen `RET`-Befehl (`0xC3`) oder eine xor-Sequenz:
  ```assembly
  xor eax, eax ; 48 31 C0 - Erfolgreicher Status (STATUS_SUCCESS)
  ret          ; C3
  ```
- **Folge:** Der Prozess verstummt telemetrisch für User-Mode ETW-Consumer.

---

## 5. In-Memory Loader Architekturen

Um dateibasierte Signaturen auf Datenträgern zu umgehen, verbleiben moderne Payloads ausschließlich im flüchtigen Speicher.

```
+-------------------------------------------------------------------+
| In-Memory Loader Verfahren im Vergleich                          |
+-------------------------------------------------------------------+
| 1. Reflective DLL Loading:                                        |
|    Allokiert privaten Speicher (RWX/RX) -> parst PE-Header        |
|    -> kopiert Sektionen -> Relocations -> IAT -> DllMain          |
|    Schwachstelle: Unbacked Memory-Regionen fallen beim Scan auf.  |
|                                                                   |
| 2. Module Stomping / DLL Hollowing:                               |
|    Lädt legitime, signierte DLL von Disk (z. B. chkdsk.dll)       |
|    -> überschreibt .text Sektion mit Payload                      |
|    Schwachstelle: Disk-vs-Memory Divergenz (File Backed Mismatch) |
|                                                                   |
| 3. Process Hollowing (RunPE):                                     |
|    Startet Zielprozess (suspended) -> Unmap Originalcode          |
|    -> schreibt Payload -> Context/EntryPoint anpassen -> Resume    |
|    Schwachstelle: Thread Creation Telemetrie & Header-Prüfung     |
+-------------------------------------------------------------------+
```

### 5.1 Reflective DLL Loading Ablauf im Detail
1. **Speicherallokation:** Reservieren eines Speicherbereichs (`VirtualAlloc` mit `PAGE_READWRITE`).
2. **Kopieren der PE-Sektionen:** Parsen der `IMAGE_SECTION_HEADER`-Strukturen und Kopieren der Sektionen (`.text`, `.rdata`, `.data`) an ihre relativen virtuellen Adressen (RVAs).
3. **Base Relocation (Wichtig):** Liegt das Image nicht an seiner bevorzugten `ImageBase`, traversiert der Loader die `.reloc`-Tabelle:
   $$\text{Zieladresse} = \text{AktuelleBase} + \text{VirtualAddress} + \text{Offset}$$
   und addiert die Differenz ($\Delta = \text{AktuelleBase} - \text{BevorzugteBase}$) auf alle absoluten Pointer.
4. **Import Address Table (IAT) Resolution:** Parsen von `IMAGE_IMPORT_DESCRIPTOR`, Laden abhängiger DLLs via `LoadLibraryA` und Eintragen von Funktionszeigern via `GetProcAddress`.
5. **Rechteanpassung:** Ändern der `.text`-Sektion auf `PAGE_EXECUTE_READ` und `.rdata` auf `PAGE_READONLY` (W^X-Prinzip).
6. **Einsprung:** Aufruf von `DllMain(hModule, DLL_PROCESS_ATTACH, NULL)`.

---

## 6. Defensive Gegenmaßnahmen & Detection Engineering

### 6.1 YARA-Regeln zur Detektion von Hook-Evasion Mustern

```yara
rule Hunt_Indirect_Syscalls_And_Evasion_Patterns {
    meta:
        description = "Erkennt generische Syscall-Stubs und AMSI-Patch-Muster in Binärdateien"
        author = "Security Research Team"
        date = "2026-11-06"
        score = 80
    strings:
        // Typisches Indirect Syscall Setup (mov r10, rcx; mov eax, ssn)
        $syscall_stub = { 4C 8B D1 B8 ?? ?? 00 00 [0-10] FF 25 }
        
        // AMSI Return Patch (mov eax, 0x80070057; ret)
        $amsi_patch = { B8 57 00 07 80 C3 }
        
        // ETW EventWrite Nulling Patch (xor eax, eax; ret)
        $etw_patch = { 48 31 C0 C3 }
        
        // Halo's Gate Opcode Search Signature (4C 8B D1 B8)
        $halos_gate = { 4C 8B D1 B8 }
    condition:
        uint16(0) == 0x5A4D and (
            ($syscall_stub and $halos_gate) or
            $amsi_patch or
            $etw_patch
        )
}
```

### 6.2 Sigma-Regeln zur Verhaltenserkennung

#### Erkennung verdächtiger Speicherschutzänderungen (RWX Allokationen)
```yaml
title: Suspicious Memory Protection Modification to RWX
id: 8d312984-7a1b-4f9e-a89c-b1b0e513e4b1
status: stable
description: Erkennt Prozesse, die Speicherschutzrechte auf PAGE_EXECUTE_READWRITE ändern, typisch für In-Memory Stager.
logsource:
    category: process_tampering
    product: windows
detection:
    selection:
        TargetProtection: 'PAGE_EXECUTE_READWRITE'
        CallTrace|contains:
            - 'UNKNOWN'
            - 'unbacked'
    filter_legit:
        ProcessCommandLine|contains:
            - 'clr.dll'
            - 'jvm.dll'
    condition: selection and not filter_legit
falsepositives:
    - JIT-Compiler (.NET, Java, Browser V8-Engines)
level: high
```

### 6.3 Härtungsmaßnahmen für Enterprise-Infrastrukturen
1. **Arbitrary Code Guard (ACG):** Verhindert das Ändern von Berechtigungen existierender Codesektionen und das Neuerzeugen von RWX-Seiten.
2. **Code Integrity Guard (CIG):** Erzwingt, dass nur von Microsoft oder WHQL-signierte Binärdateien und DLLs in geschützte Prozesse geladen werden dürfen.
3. **Protected Process Light (PPL):** Schutz kritischer Prozesse (wie EDR-Dienste und `lsass.exe`) vor externem Handle-Zugriff aus Ring 3.

---

## Quellen
- [Q4] VulnQuest – EDR Evasion in 2025: What Still Works and Why
- [Q7] Picus Security – The Ransomware Attack Lifecycle from the Defender's Perspective
- [Q67] vx-underground – The Art of Syscall Bypasses: Hell's Gate, Halo's Gate & Tartarus' Gate
- [Q68] Outflank – In-Depth Analysis of Direct vs. Indirect Syscalls
- [Q69] Mandiant – Evading EDR with Call Stack Spoofing and Memory Scanning Bypasses
