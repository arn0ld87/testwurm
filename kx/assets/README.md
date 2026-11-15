# Assets

Werkzeuge, die der Agent auf dem **Agenten-Host** ausführt — nicht auf dem Ziel.

## `smbrelayx.py`

| | |
|---|---|
| Herkunft | [Impacket](https://github.com/fortra/impacket) 0.11.0, `examples/smbrelayx.py` |
| Copyright | Copyright (C) 2023 Fortra. All rights reserved. |
| Lizenz | modifizierte Apache-Lizenz — vollständiger Text in [`IMPACKET-LICENSE.txt`](./IMPACKET-LICENSE.txt) |
| Prüfsumme | `sha256:74e6c5278900fb57cdfe7945ffecd94c4a50c262faafb4c899b75462ba206564` |

Das Skript relaidet SMB-Anfragen an einen Domaincontroller und führt dort ein
Kommando aus. Im Agenten ist das `mimikatz.exe "lsadump::hashes"` — der
Kommando-Output landet auf stdout und wird nach NT-Hashes geparst.

### Voraussetzungen auf dem Agenten-Host

Das Skript braucht das Impacket-Paket, nicht nur die Datei:

```bash
pip3 install impacket
```

Zusätzlich braucht das Ziel Mimikatz (`mimikatz.exe`) — es wird über den
SMB-Relay-Aufruf auf dem Ziel ausgeführt.

### Aufruf

Der Agent ruft das Skript so auf:

```bash
python3 assets/smbrelayx.py -h <ziel> -domain <domain> -c "<kommando>" -one-shot
```

`--relay-script` überschreibt den Pfad, wenn das Asset woanders liegt. Der
Pfad ist relativ zum Arbeitsverzeichnis des Agenten — also startet der Agent
aus dem `kx`-Verzeichnis des Repositories.

### Warum Version 0.11.0

Ab Impacket 0.12 gibt es `smbrelayx.py` nicht mehr. Das Skript wurde zu
`ntlmrelayx.py` umgebaut — ein interaktiver Server, der von stdin liest und
endlos läuft. Das passt nicht zum Exploit-Ablauf des Agenten, der einen
einzelnen Versuch mit begrenzter Laufzeit braucht. 0.11.0 ist die letzte
Version mit dem einmaligen Aufruf und steht unter derselben Apache-Lizenz.
