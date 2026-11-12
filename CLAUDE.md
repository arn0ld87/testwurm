# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is a hacking/pentesting toolkit repository containing various security tools and utilities for authorized penetration testing and red team operations.

The repository root carries **no source code**. All executable code lives in the Rust
workspace under `kx/`:

| Path | Content |
|------|---------|
| `kx/` | Rust workspace, 9 member crates — scanner, exploit, post-exploitation (Windows/POSIX), TLS, C2 server, agent, operator CLI |
| `docs/` | Agent documentation (issue-tracker and domain conventions) and ADRs. No source code |
| `wissen/` | Research knowledge base (28 Markdown files on ransomware technique, kill chains, crypto and C2). No source code |

The worm's pipeline runs through the phases Entdeckung → Scan → Exploit → Extraktion →
Persistenz → Reporting. The overview and the authoritative list of global invariants live in
[`README.md`](./README.md); the crate contract layer lives in [`kx/crates/README.md`](./kx/crates/README.md)
and the per-crate `README.md` files under `kx/crates/<crate>/`.

## Development Environment

- **Primary Language**: Rust (Edition 2021, MSRV 1.77, `resolver = "2"`)
- **Package Management**: Cargo workspace — `kx/Cargo.toml` holds the workspace manifest and the single pinned version location per dependency
- **Testing Framework**: built-in `#[test]` harness (`cargo test --workspace`)
- **Code Quality**: `cargo fmt`, `cargo clippy`, `cargo audit`

Toolchain (Rust 1.99.1, `rustup` under `~/.rustup`) needs its PATH set per shell:

```bash
export PATH="$HOME/.cargo/bin:$PATH"
```

## Common Development Commands

All commands run from the workspace root `kx/` unless noted otherwise.

```bash
# Build the whole workspace
cargo build --workspace --all-targets

# Run all tests
cargo test --workspace

# Format check / format
cargo fmt --check
cargo fmt

# Lints
cargo clippy --workspace --all-targets -- -D warnings

# Dependency vulnerability audit (requires `cargo audit`)
cargo audit

# Release build of the C2 server only
cargo build --release -p kx-server

# Start smoke test (must answer 401 / 401 / 200 / 404 — see .github/workflows/ci.yml)
./target/release/kx-server --host 127.0.0.1 --port 8443 --db /tmp/kx.db --token test
```

## Architecture Notes

- **Crate layering is strict**: `kx-core` and `kx-scanner` are base layers without internal
  crate dependencies; `kx-agent` is the only crate that binds all domains together.
- **Platform effects are `cfg`-gated**: `kx-win` and `kx-posix` hide every external effect
  behind a `cfg` pair, so the workspace compiles on any platform; the non-target stubs are inert.
  `kx-scanner/src/arp.rs` is fully `#[cfg(target_os = "linux")]`.
- **TLS**: `kx-tls` only ever produces self-signed certificates without a CA chain; the client
  trust store stays empty and holds only the passed PEM certificates.
- **C2 contract**: the Bearer token is enforced by middleware on a dedicated API subrouter
  (`route_layer`). The five contract paths answer 401 without a valid token, an unknown path
  answers 404 — an outsider learns nothing about which paths exist. The dashboard is exempt and
  authenticates via `POST /api/login`; the token lives in a JavaScript variable, not in the URL.
- **Dashboard escaping**: every API value is escaped before it reaches the table. A
  target-controlled hostname is foreign data.
- **Pinned dependency**: `ml-kem` is pinned to `=0.2.3` and resolved through
  `workspace = true` — exactly one version location. See the comment block in
  `kx/Cargo.toml` for why 0.2.3 and not 0.2.1 or 0.3.x. `kx-core/src/hostkey.rs` still uses an
  `ml-kem` API that exists in no released 0.2.x — the module must be rewritten onto an API that
  actually exists (ISSUE-9).
- **Release profile**: `panic = "unwind"` is deliberate — the encoder catches a panic per file so
  a single failure does not end the run. The dev profile keeps `opt-level = 1` so debug asserts
  stay live and crypto edge cases do not pass silently.

### Global invariants

- The entire repository is for **authorized penetration tests and red-team exercises only**;
  use without express authorization is illegal.
- The canonical terminology (Wurm, C2, Exfiltration, Persistenz, CVE, Payload, Vector,
  Reconnaissance, Lateral Movement, Privilege Escalation, IOC, Telemetrie) is fixed in
  [`GLOSSARY.md`](./GLOSSARY.md) and binding for all crates.
- Global side effects are enumerated in [`README.md`](./README.md) under *Global Side Effects* —
  network sweeps, SMB-Relay via Impacket, `mimikatz.exe`/`powershell.exe` on Windows,
  `systemctl`/`crontab` on POSIX, and plaintext secret export by the CLI. Check that section
  before changing any of it.

## Security Considerations

All tools are designed for **authorized penetration testing only**. Ensure proper authorization before use in any environment. Tools should implement:

- Clear scope boundaries to prevent accidental overreach
- Comprehensive logging for audit trails
- Kill switches for immediate termination
- Data encryption for sensitive information

## Code Organization

```
kx/
├── Cargo.toml              # workspace manifest, shared deps, profiles
└── crates/
    ├── kx-core/            # c2 (protocol module), format (KXENC), hostkey, util
    ├── kx-scanner/         # arp (Linux only), tcp_scan, fingerprint
    ├── kx-exploit/         # smb_relay, wmi_exec, credential_stuff, payload
    ├── kx-win/             # secrets (LSASS/CredMan), persist (tasks, run keys, sc)
    ├── kx-posix/           # secrets (shadow, SSH, AWS), persist (systemd, cron)
    ├── kx-tls/             # self-signed certs, client trust store
    ├── kx-agent/           # propagate (scan→exploit loop), c2 (client), main
    ├── kx-server/          # auth (Bearer middleware), db (SQLite), dashboard, main
    └── kx-cli/             # client (C2 requests), main (hosts/secrets/tasks/export)
```

## Verification and CI

`.github/workflows/ci.yml` runs two jobs:

- **build** — `cargo build --workspace --all-targets` and `cargo test --workspace` on
  ubuntu-latest *and* macos-latest, because the workspace must build on both platforms.
- **smoke** — starts the release `kx-server` and asserts the authentication contract over TLS
  (401 without token, 401 with wrong token, 200 with correct token, 404 for an unknown path).

The CI has **deliberately no fmt and no clippy gate**: `cargo fmt --check` currently reports a
large number of formatting deviations, and enforcing it would force an unrelated reformat
commit. Keep formatting and lint cleanup as their own workstream.

## Current work

Open defects are tracked as local Markdown issues under `.scratch/<feature>/issues/`. The
`c2-operability` epic has completed wave 1 (ISSUE-1, ISSUE-8, ISSUE-10, ISSUE-12, ISSUE-13);
wave 2 is open. See [`EPIC.md`](./.scratch/c2-operability/EPIC.md) for the dependency order and
[`design_draft.md`](./.scratch/c2-operability/design_draft.md) for the design and the decisions
D1–D7.

## Agent skills

### Stack-correct tooling

The repository is **Rust** — use the Rust skill path, not the Python one:

| Need | Use |
|------|-----|
| Review changed Rust code | `/rust-review` (ownership, lifetimes, `unsafe`, clippy, `cargo audit`) |
| Fix build / borrow-checker / dependency errors | `/rust-build` |
| TDD for Rust, coverage check | `/rust-test` |
| Bug → failing regression test → fix → review → gated commit | `/orch-fix-defect` |
| Behavior change in existing code | `/orch-change-feature` |
| New capability | `/orch-add-feature` |
| Multi-dimensional review with adversarial verification | `/orch-review`, `/code-review` |
| Operator-side security review (auth, dashboard, export, token handling) | `ecc:security-review`, `ecc:security-reviewer` |
| C2 REST contract review | `ecc:api-design` |
| SQLite schema review | `ecc:database-reviewer` |
| ADRs under `docs/adr/` | `ecc:architecture-decision-records` |
| Knowledge base under `wissen/` | `ecc:knowledge-ops` |

Note: `ecc:epic-*` commands are GitHub-backed (`github-coordination.js --repo <owner/repo>`) and
do **not** apply here — this repository's tracker is local Markdown (see below).

### Issue tracker

Local markdown issues under `.scratch/<feature>/issues/`. See `docs/agents/issue-tracker.md`.

### Domain docs

Single-context layout with `GLOSSARY.md` and `docs/adr/` at repo root. See `docs/agents/domain.md`.
