---
id: ISSUE-15
title: Das KXENC-Containerformat hat keine Chiffre — Dateiexfiltration ist nicht möglich
status: open
priority: medium
category: enhancement
triage_state: needs-triage
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

## Technical Notes

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
