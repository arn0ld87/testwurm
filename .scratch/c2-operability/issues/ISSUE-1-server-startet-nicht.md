---
id: ISSUE-1
title: kx-server startet nicht — mehrdeutige rustls-CryptoProvider-Auflösung
status: done
priority: high
---

## Description

Der C2-Server paniked beim Start mit:

```
Could not automatically determine the process-level CryptoProvider from Rustls crate features.
Call CryptoProvider::install_default() before this point to select a provider manually,
or make sure exactly one of the 'aws-lc-rs' and 'ring' features is enabled.
```

Ursache: Der Workspace deklariert `rustls = { version = "0.23.27", default-features = false, features = ["ring", ...] }` und aktiviert damit `ring`. Gleichzeitig zieht `rustls 0.23.46` über `rustls-webpki 0.103` **aws-lc-rs** hart mit — die Dependency ist in dieser webpki-Version nicht optional. Damit sind **beide** Provider im Feature-Set, und `ServerConfig::builder()` / `ClientConfig::builder()` in `kx-tls/src/lib.rs:54` und `:79` lösen den prozessweiten Provider nicht auf.

`CryptoProvider::install_default()` ruft im gesamten Workspace niemand auf (verifiziert per `grep -rn "install_default" crates/` → kein Treffer).

Damit ist der komplette dokumentierte Betriebsablauf blockiert: Schritt „C2-Server starten" in `kx/README.md` ist nicht ausführbar, und mit dem Server fällt auch der Agent aus (er kann sich nicht registrieren).

Verifiziert am 2026-11-11 per Start-Smoke-Test:
`./target/debug/kx-server --host 127.0.0.1 --port 18443 --db /tmp/kx-drift-smoke.db --token smoketest --cn kx.local`

Related: ISSUE-2, ISSUE-7

## Acceptance Criteria

- [x] `kx-server` startet ohne Panic und lauscht auf dem konfigurierten `host:port` — verifiziert per Start-Smoke-Test (2026-11-11): Der Server lauscht und antwortet mit der API-Übersicht
- [x] Genau ein CryptoProvider ist aktiv — `axum-server` nutzt das Feature `tls-rustls-no-provider`, `aws-lc-rs` ist mit 0 Vorkommen aus dem Lockfile verschwunden, und `kx_tls::install_crypto_provider()` setzt den Provider explizit
- [ ] Ein Test deckt den Startpfad ab: `generate_server_tls` + `client_config_trusting` müssen ohne Panic durchlaufen — **noch offen**: `install_crypto_provider()` wird in beiden Funktionen aufgerufen, aber `kx-tls` hat kein eigenes Testmodul. Bisher nur der manuelle Smoke-Test
- [x] `cargo test --workspace` bleibt grün (Stand: 59 Tests, 0 Fehler)

## Technical Notes

- Betroffen: `kx/Cargo.toml:49` (rustls-Features), `kx/crates/kx-tls/src/lib.rs` (Provider-Auflösung)
- Variante A: `CryptoProvider::install_default(CryptoProvider::ring)` beim Start von `kx-tls` aufrufen — explizit und robust gegen künftige Feature-Änderungen
- Variante B: `ring` aus dem rustls-Feature-Set entfernen und aws-lc-rs verwenden — konsistent mit der Transitiv-Auflösung, aber `ring` ist oft schneller und bereits im Workspace vorgesehen
- Variante C: rustls auf eine Version pinnen, deren `rustls-webpiki` ohne hartes aws-lc-rs auskommt — die `0.23.27`-Angabe im Manifest ist nur eine Untergrenze, aufgelöst wird `0.23.46`
- Achtung: `Cargo.lock` ist nicht im Repo-Commit enthalten; eine reine Manifest-Änderung verschiebt die Auflösung. Ein expliziter `install_default()` ist die robusteste Variante, weil sie unabhängig von der Auflösung funktioniert
- Der Panic ist ein `panic!` in rustls, kein `Result` — die Auflösung lässt sich per `catch_unwind` nicht sauber abfangen, der Provider muss also vor dem ersten Builder-Aufruf gesetzt sein
