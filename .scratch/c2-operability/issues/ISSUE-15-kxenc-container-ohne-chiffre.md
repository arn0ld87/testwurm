---
id: ISSUE-15
title: Das KXENC-Containerformat hat keine Chiffre — Dateiexfiltration ist nicht möglich
status: open
priority: medium
handoff: briefs/ISSUE-15-handoff.md
category: enhancement
triage_state: spezifiziert
---

## Description

`kx-core/src/format.rs` beschreibt das KXENC-Dateiformat: Header, Footer,
Range-Offsets, Chunk-Nummerierung, AAD-Berechnung, Nonce-Ableitung. Der Code ist
korrekt und getestet — aber er **verschlüsselt nichts**. Die Chiffre fehlt
vollständig:

- Es gibt keine Funktion, die einen Chunk mit ChaCha20-Poly1305 verschlüsselt.
- Das Feld `wrapped_dek` im Footer ist ein Platzhalter, kein tatsächlich
  gewrappter Dateischlüssel.
- `aad_for` und `nonce_for` werden nur von den Tests benutzt. Verifiziert mit
  der semantischen Suche im Code-Graph: 0 Call-Sites außerhalb der Testmodule.
  Für die Suche nach einer Datei-Chiffre liefert der Graph ausschließlich
  Layout-Funktionen (`chunk_iter`, `chunks_for_ranges`, `Range`, `ChunkRef`).

Der Agent exfiltriert heute ausschließlich Passwörter und NT-Hashes. Dateien
können nicht exfiltriert werden — es gibt weder einen Aufrufer noch einen Weg,
ihre Daten zu verpacken. Das `format`-Modul ist damit eine tote Bibliothek: nur
`KexId` wird benutzt, der Rest nicht.

Die Secret-Exfiltration nimmt einen anderen Weg: `kx-core/src/secretbox.rs`
verschlüsselt jedes Passwort einzeln mit ChaCha20-Poly1305, der Schlüssel
kommt per HKDF aus dem Master-Key. Dieser Weg ist geschlossen, getestet und in
Betrieb.

## Spezifikation (2026-11-16, aus der Code-Analyse abgeleitet)

Sechs Befunde, die die Umsetzung präzisieren. Zwei davon korrigieren die
Aufgabenprämisse.

**1. KXENC hat keinen Header.** Die Datei beginnt mit dem verschlüsselten Kopf
der Originaldatei; Magic (`KXNF`), Formatversion, Cipher- und KEX-Kennung
stehen ausschließlich im **Footer** am Dateiende (`off::MAGIC=0`,
`off::VERSION=4`, `off::CIPHER=5`, `off::KEX=6`). Es gibt genau eine
Formatversion (`FORMAT_VERSION=1`, `READABLE_FORMAT_VERSIONS=[1]`) und kein
Forward-Kompatibilitätsraster. Der Footer ist das einzige
Selbstbeschreibungsstück; als Container-Identität dient `file_id` (16 Byte,
Footer-Offset 20).

**2. `secretbox` ist String-/UTF-8-only.** `seal` liefert einen String mit
`kx1:`-Präfix und Base64, `open` erzwingt UTF-8. Das Wrapping des
Dateischlüssels braucht eine byte-orientierte Variante: der gewrappte DEK
ist binär (44 Byte Klartext im 72-Byte-Feld). Nötig sind `seal_bytes` und
`open_bytes` mit eigenem Info-String (`b"kx/kxenc-dek/v1"`) und eigenem Salt;
die bestehenden String-Funktionen bleiben als dünne Wrapper darüber erhalten,
damit die Secret-Exfiltration unverändert bleibt.

**3. Die Chunk- und Reichweiten-Parameter sind unbestimmt.** `plan_ranges`
erzeugt höchstens zwei Reichweiten (Kopf und Fuß) — das Mittelfeld bleibt
unberührt und damit im Klartext. Ohne Festlegung wäre „der Container
verschlüsselt die Datei" eine halbe Wahrheit. Festlegung: `head_len =
plain_size` (Vollverschlüsselung, eine einzige Reichweite über die ganze
Datei), `tail_len = 0`, `min_size = 1`, `chunk_size = 1 MiB`. Die
Kopf/Fuß-Variante bleibt als Modus im Code, wird für ISSUE-15 aber nicht
benutzt.

**4. Der Container trägt keine Frische.** `created_unix` steht im Footer, ist
aber nur unkeyed CRC32-geschützt, und es gibt keinen monotonen Zähler je
Host: Ein erneut eingespielter Container entschlüsselt sich fehlerfrei, der
Operator sieht eine alte Datei als neue. Semantik: Der Server dedupliziert
je `(host_id, file_id)`, und die `file_id` steht in der AAD — ein wiederholter
Upload mit gleicher `file_id` wird abgewiesen. Ein authentifizierter
Zeitstempel in der AAD wäre Formatversion 2 (das AAD-Label `KXENC-AAD1` ist
Teil des Formats) und gehört in eine spätere Welle.

**5. Das Layout schreibt „in Place".** Das hat zwei Folgen: Der Container, der
auf der Zielplatte liegt, enthält die Mitte der Beute im Klartext; und wer
den Container in place erzeugt, überschreibt die Originaldatei — ein
Operator, der nie kommt, verliert die Daten. Betriebsvertrag: Der Encoder
schreibt eine **neue Datei neben das Original** (`<name>.kxenc`) und lässt
das Original unangetastet. Das Löschen des Originals ist eine eigene,
ausdrücklich freizugebende Entscheidung (Ransomware-Verhalten, für einen
autorisierten Pentest nicht Default).

**6. Scope.** Ein KXENC-Container trägt genau **eine** Datei (eine `file_id`,
eine `plain_size`, ein `wrapped_dek`). Verzeichnisbäume (ein ganzes
`~/.config/gcloud`, ein Browserprofil) brauchen ein Manifest über mehrere
Container — das ist eine Format-Erweiterung und eine eigene ADR. Ebenso ist
der Container für kleine Textartefakte (SSH-Keys, Cloud-Dateien, `kubeconfig`,
`.npmrc`, `.netrc`) reine Zusatzkomplexität: Der bestehende
Einzel-Secret-Transport trägt sie. Die eigene Recherche des Repos stuft den
Container ausdrücklich nur für Registry-Hives (SAM/SYSTEM/SECURITY, ~30 MB)
und `NTDS.dit` als gerechtfertigt ein.

**Scope von ISSUE-15:** Chiffre + Container-Format + Roundtrip-Test +
Transport für eine einzelne Binärdatei. Referenzlast: Registry-Hive (~30 MB).
Verzeichnisbäume, Extraktoren für Textartefakte und das Löschen des Originals
sind eigene Issues.

### Drei Entscheidungen (Maintainer)

| Frage | Empfehlung | Begründung |
|---|---|---|
| DEK pro Datei oder deterministisch aus dem Master-Key? | **pro Datei** | Nur so lässt sich eine Datei einzeln widerrufen; ein deterministischer DEK gäbe allen Dateien denselben Schlüssel. |
| Versionierung und Wiederverwendung von `range_sha256`? | **Footer trägt Version 1, `range_sha256` bleibt ungenutzt** | `range_sha256` hat keine AAD-Bindung; ihn einzuführen wäre eine Formatversion 2. |
| Vollverschlüsselung oder Kopf/Fuß? | **Vollverschlüsselung** (`head_len = plain_size`) | Der Kopf/Fuß-Modus lässt die Dateimitte im Klartext — für Beute, die geheim bleiben soll, ist das keine Option. |

## Acceptance Criteria

- [ ] Eine Chiffre verschlüsselt Chunks mit ChaCha20-Poly1305 und der AAD aus
      `aad_for` — Umsortieren oder Duplizieren von Chunks schlägt fehl
- [ ] Der Dateischlüssel (DEK) wird pro Datei erzeugt und im Footer gewrappt
      gespeichert; der Empfänger entpackt ihn mit dem privaten KEM-Schlüssel
- [ ] Die Nonce-Ableitung aus `nonce_for` wird genutzt — ein Nonce je Chunk,
      an den Chunk-Index gebunden
- [ ] Der Agent exfiltriert eine Datei als Container, der Operator kann sie
      entschlüsseln
- [ ] Ein Roundtrip-Test deckt den ganzen Weg ab: verschlüsseln, lesen,
      entschlüsseln — inklusive Erkennung eines einzelnen Bit-Flips
- [ ] Der Encoder schreibt eine neue Datei **neben** das Original
      (`<name>.kxenc`); das Original bleibt unangetastet. Kein In-Place-Schreiben
- [ ] Vollverschlüsselung: `head_len = plain_size`, `chunk_size = 1 MiB` — die
      Dateimitte steht an keiner Stelle im Klartext im Container
- [ ] `secretbox` bekommt `seal_bytes`/`open_bytes` mit eigenem Info-String
      (`b"kx/kxenc-dek/v1"`); die bestehenden String-Funktionen bleiben als
      Wrapper erhalten
- [ ] Die `file_id` steht in der AAD; der Server dedupliziert je
      `(host_id, file_id)` und weist einen wiederholten Upload ab
- [ ] Ein Test belegt, dass ein Klartext-Snippet der Originaldatei im fertigen
      Container **nicht** vorkommt

## Technical Notes

**Korrektur bei der Architekturprüfung (2026-11-15):** `format.rs` ist **nicht
vollständig tot**. `KexId` (`format.rs:89`) ist im lebenden Kryptografie-Pfad
load-bearing — `kx-core/src/hostkey.rs` greift an 20 Stellen darauf zu, dazu
kommen `kx-core/examples/gen_server_key.rs` und `kx-server/src/e2e_test.rs`.
Toter ist nur der Container-Anteil: `Footer`, `Range`, `ChunkRef`,
`plan_ranges`, `aad_for`, `CipherId`.

**Vorbedingung:** ISSUE-15 muss zuerst `KexId` aus dem Container-Modul herauslösen
(eigener Typ in `kx-core/src/hostkey.rs` oder ein neues Modul). Wer das
Container-Modul vorher löscht, bricht die laufende Kryptografie.

- `kx-core/src/format.rs` ist der natürliche Ort für die Chiffre; die
  Layout-Funktionen sind getestet und bleiben unverändert.
- `kx-core/src/secretbox.rs` bringt ChaCha20-Poly1305 als Dependency mit und
  zeigt das Muster: Nonce im Ciphertext, HKDF-Ableitung, Zeroize nach Gebrauch.
- `kx-core/src/hostkey.rs` liefert das Schlüsselmaterial (`ServerKeyPair`,
  `unseal_master_key`) für das Wrapping des DEK.
- Das Modul-Doc von `kx-core/src/lib.rs` nennt eine Schichtung
  `format → crypto → engine → beacon` aus einem Vorgängerprojekt. Der
  `crypto`-Teil ist genau diese Lücke.
- Der Footprint ist ein Container pro Datei. Header und Footer stehen fest, die
  Chunks folgen im Chiffratstrom.

Related: ISSUE-9
