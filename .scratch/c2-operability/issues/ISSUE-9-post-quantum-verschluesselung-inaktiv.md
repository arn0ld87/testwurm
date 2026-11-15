---
id: ISSUE-9
title: Post-Quantum-Verschlüsselung der Beute ist inaktiv — hostkey-Modul nicht kompiliert
status: open
category: bug
triage_state: ready-for-agent
agent_brief: briefs/ISSUE-9-post-quantum-aktivieren.md
priority: high
---

## Description

Das Crate `kx-core` enthält den vollständigen Code für hybride Post-Quantum-Schlüsselung (`kx-core/src/hostkey.rs`, 16 KB): X25519 + ML-KEM-768, HKDF, Argon2id, `ServerKeyBundle`, `ServerKeyPair`, `MlKemSecret` mit Zeroize-Drop. **Keine Zeile davon ist Teil des Builds.**

`kx-core/src/lib.rs:13` (früher Zeile 12):

```rust
// pub mod hostkey;  // TODO: ml-kem 0.2.1-API-Anpassungen noetig, vorerst deaktiviert
```

Das Modul ist damit nicht Teil der öffentlichen API, und die Implementierung ist zusätzlich **nicht übersetzbar**:

1. `derive_master_key` wird an vier Stellen aufgerufen, aber nirgends definiert.
2. `hostkey.rs` importiert `rand::RngCore` — `rand` ist nur eine Dev-Dependency (`kx-core/Cargo.toml`), `rand_core` ist die reguläre Dependency. Die eigene `impl rand_core::RngCore for MlRng<'_>` (`hostkey.rs:410`) zeigt, dass der Import auf `rand_core` umgestellt werden muss.
3. Die `ml-kem`-Imports passen nicht zur Version 0.2.1 (die im Manifest deklarierte Version löst ohnehin auf 0.2.3, siehe ISSUE-8).

Selbst wenn das Modul kompiliierte, wären zwei Verhaltensfehler latent:

- `derive_master_key_with_context` liefert laut Code **stets 32 Null-Bytes** — das HKDF-Ergebnis wird verworfen (`copy_nonoverlapping` mit Länge 0).
- Im X25519-only-Modus erzeugt `encapsulate_host_master_key` ein 32-Byte-`sealed_master`, während `unseal_master_key` exakt `SEALED_MASTER_LEN` = 1120 Byte verlangt. Der Roundtrip ist in diesem Modus nicht schließbar.

Konsequenz: Die Beute wird derzeit **nicht** post-quantum-verschlüsselt. `kx/README.md` hat das bis zur Correction Policy als Hauptmerkmal geführt; die Korrektur stellt klar, dass der Pfad nicht aktiv ist.

Related: ISSUE-8

## Acceptance Criteria

- [ ] `pub mod hostkey;` ist in `kx-core/src/lib.rs` aktiv und `kx-core` kompiliert
- [ ] `derive_master_key` ist definiert und liefert ein echtes HKDF-Ergebnis — keine 32 Null-Bytes
- [ ] Der Seal/Unseal-Roundtrip ist im X25519-only-Modus schließbar (Längen konsistent)
- [ ] `rand::RngCore` ist durch `rand_core::RngCore` ersetzt, sodass nur reguläre Dependencies nötig sind
- [ ] Die `ml-kem`-Imports passen zur aufgelösten Version (0.2.1 oder 0.2.3, siehe ISSUE-8)
- [ ] `MlKemSecret` und die X25519-Secrets werden nach Gebrauch genullt (Zeroize) — der `Drop`-Impl existiert, ist aber ungetestet
- [ ] Ein Test prüft den vollständigen Roundtrip: Bundle erzeugen → public exportieren → einschließen → entschlüsseln → Klartext stimmt

## Technical Notes

- Betroffen: `kx-core/src/lib.rs:13` (auskommentiert), `kx-core/src/hostkey.rs` (416 Zeilen, nicht übersetzbar)
- Argon2id-Kosten: `m = 65_536 KiB` (64 MiB), `t = 3`, `p = 4` — pro Generierung werden rund 64 MiB alloziert. Auf einem Zielsystem mit wenig RAM ist das relevant
- `HostKeyEncapsulation.ephemeral_x25519_secret` wird laut Feld-Dokumentation mit dem **DH-Shared-Secret** gefüllt (`*x_shared.as_bytes()`), nicht mit dem ephemeren Secret — der Feldname ist irreführend, und für dieses Feld existiert kein `Drop`/Zeroize. Entweder umbenennen oder den echten Schlüssel speichern
- `MlRng::try_fill_bytes` gibt stets `Ok(())` zurück und verschluckt Fehler des gewrappten RNG — ein Fehler der Entropiequelle bliebe unbemerkt
- `ARGON2_SALT_LEN` (16) wird nirgends geprüft — `argon2id` validiert die Salt-Länge nicht
- Der `TODO`-Kommentar nennt „ml-kem 0.2.1-API-Anpassungen" — das ist die Ursache, die mit ISSUE-8 (falsch aufgelöste Version) zusammenhängt

## Triage Notes

**Verifiziert am 2026-11-15 gegen `origin/main` (74 Tests grün):**

- Der Befund ist bestätigt: die Modul-Deklaration des KEM-Moduls ist
  auskommentiert, das Modul wird nicht kompiliert, und der Agent sendet die
  Master-Key-Felder des C2-Vertrags leer.
- Die Voraussetzung ist erfüllt: der `ml-kem`-Pin steht auf einer konkreten
  Version. Die API des Moduls passt zu dieser aufgelösten Version noch nicht —
  das ist der eigentliche Arbeitsanteil, kein fehlender Pin.

**Triage-Entscheidung:** Agent Brief: [`briefs/ISSUE-9-post-quantum-aktivieren.md`](briefs/ISSUE-9-post-quantum-aktivieren.md)
