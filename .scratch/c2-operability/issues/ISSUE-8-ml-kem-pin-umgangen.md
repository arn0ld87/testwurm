---
id: ISSUE-8
title: ml-kem-Pin im Workspace wird von kx-core umgangen — 0.2.3 wird aufgelöst
status: done
priority: medium
---

## Description

Der Workspace pinnt die Krypto-Bibliothek fest:

```toml
# kx/Cargo.toml:42
ml-kem = { version = "=0.2.1", default-features = false, features = ["std", "zeroize"] }
```

Der einzige konsumierende Crate deklariert `ml-kem` aber **eigenständig**, ohne `workspace = true` und ohne `=`-Pin:

```toml
# kx/crates/kx-core/Cargo.toml:24
ml-kem = { version = "0.2.1", default-features = false, features = ["std", "zeroize"] }
```

`version = "0.2.1"` ist eine Caret-Anforderung und erlaubt jede `0.2.x`-Version. `kx/Cargo.lock` löst tatsächlich **0.2.3** auf. Der Pin im Workspace-Manifest ist damit wirkungslos.

Warum das relevant ist: Der Manifest-Kommentar begründet den Pin — 0.3.x hebt `rand_core` auf 0.10 und bricht damit `x25519-dalek 2` und `rand 0.8`. Diese Absicherung greift nicht, sobald ein Crate den Workspace-Eintrag umgeht. Eine ungewollte Auflösung auf 0.3.x würde den Build brechen, statt kontrolliert zu scheitern.

Verifiziert am 2026-11-11: `grep -A2 'name = "ml-kem"' kx/Cargo.lock` → `version = "0.2.3"`.

Related: ISSUE-9

## Acceptance Criteria

- [x] Es gibt genau eine Quelle für die `ml-kem`-Version: `kx-core/Cargo.toml` verwendet `ml-kem = { workspace = true }` — verifiziert: `kx-core/Cargo.toml:26` lautet `ml-kem.workspace = true`
- [x] Der Workspace-Pin steht auf **`=0.2.3`**, nicht auf `=0.2.1` — siehe „Korrektur zum ursprünglichen Ansatz" unten
- [x] `kx/Cargo.lock` löst `ml-kem` auf **0.2.3** auf, `kem` auf `0.3.0-pre.0` und es existiert genau **eine** `rand_core`-Version (0.6.4) — verifiziert
- [x] `cargo check --workspace --all-targets` ist grün
- [x] Ein Kommentar hält fest, welche Version aufgelöst wird — der Lockfile ist ausgeschlossen (`kx/.gitignore:13`) und allein kein Schutz; der Kommentar steht in `kx-core/Cargo.toml:17`

## Technical Notes

- Betroffen: `kx/crates/kx-core/Cargo.toml:24`, `kx/Cargo.toml:42`
- `Cargo.lock` ist über `kx/.gitignore:13` ausgeschlossen und damit nicht Teil des Repositories — der Pin im Manifest ist die einzige verlässliche Absicherung, und genau die ist derzeit wirkungslos
- Der Pin ist momentan ohne praktische Folge, weil `hostkey.rs` ohnehin nicht kompiliert wird (`pub mod hostkey;` ist in `kx-core/src/lib.rs` auskommentiert) — sollte das Modul reaktiviert werden, ist die Absicherung aber zwingend

## Korrektur zum ursprünglichen Ansatz (verifiziert 2026-11-11)

Der ursprüngliche Ansatz dieses Issues war, den Workspace-Pin auf `=0.2.1` zu
übernehmen. **Das bricht den Build.** `ml-kem` 0.2.1 verlangt `kem` mit der
Caret-Version `0.3.0-pre.0`, nicht mit `=0.3.0-pre.0` wie 0.2.3. Der
Caret-Bereich lässt `kem` 0.3.0 zu, und das zieht `rand_core` 0.10.1 neben die
0.6.4 des Workspaces. Die Folge sind inkompatible Trait-Definitionen —
18 Compile-Errors, bereits in `ml-kem` selbst:

```
error[E0437]: type `Error` is not a member of trait `::kem::Decapsulate`
error[E0407]: method `encapsulate` is not a member of trait `::kem::Encapsulate`
error[E0107]: trait takes 0 generic arguments but 2 generic arguments were supplied
error[E0053]: method `decapsulate` has an incompatible type for trait
error: could not compile `ml-kem` (lib) due to 18 previous errors
```

Nachgemessen in einer Wegwerf-Kopie des Workspaces:

| Schritt | Auflösung | Build |
|---|---|---|
| `=0.2.1`, Lockfile unverändert | `ml-kem` 0.2.1, `kem` 0.3.0-pre.0, `rand_core` 0.6.4 | grün |
| `=0.2.1`, volle Neuauflösung (`cargo update`) | `ml-kem` 0.2.1, `kem` **0.3.0**, `rand_core` **0.6.4 + 0.10.1** | **18 Errors** |

Die erste Zeile täuscht: Cargo behält den bereits gelockten `kem`-Eintrag
`0.3.0-pre.0` und rechnet die transitiven Abhängigkeiten nicht neu. Erst die
vollständige Neuauflösung zeigt den Konflikt. Genau deshalb ist der
Lockfile als Absicherung untauglich — er ist nicht einmal im Repository.

**Korrekte Entscheidung:** den Workspace-Pin auf **`=0.2.3`** anheben und
`kx-core` auf `workspace = true` umstellen. `ml-kem` 0.2.3 pinnt `kem` exakt
auf `=0.3.0-pre.0`, bleibt damit bei `rand_core` 0.6.4 und baut sauber.

## Abgrenzung zu ISSUE-9

Der Pin-Fix allein stellt die Post-Quantum-Fähigkeit **nicht** wieder her. Die
von `hostkey.rs` erwartete API existiert in **keiner** veröffentlichten
`ml-kem`-Version:

| von `hostkey.rs` erwartet | ml-kem 0.2.1 | ml-kem 0.2.3 |
|---|---|---|
| `ml_kem::bihash::Sha3_256` | fehlt | fehlt |
| `ml_kem::EncodedKey` | fehlt | fehlt |
| `ml_kem::MlKem768Derive` | fehlt | fehlt |
| `ml_kem::SecretKey` | fehlt | fehlt |
| `ml_kem::generate_keypair` | fehlt | fehlt |
| `ml_kem::decapsulated_key_from_encoded` | fehlt | fehlt |
| `ml_kem::EncodedSizeByteLen` | fehlt | fehlt |
| `ml_kem::Secret` | fehlt | fehlt |
| `ml_kem::encapsulated_key` | fehlt | fehlt |
| `ml_kem::secret_key_from_bytes` | fehlt | fehlt |
| `ml_kem::Array` | vorhanden | vorhanden |

`hostkey.rs` ist also gegen eine API geschrieben, die es nicht gibt. Das ist
der eigentliche Defekt und gehört nach ISSUE-9, nicht nach ISSUE-8.
