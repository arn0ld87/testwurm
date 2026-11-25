# Testwurm · Präsentations-Targets
.PHONY: start setup test check lint e2e graph crg clean-lab

start: ## GUI + Labor starten (ein Befehl für die Präsentation)
	./start.sh

setup: ## Labor-Images und Netz bauen (idempotent)
	./lab/setup.sh

test: ## Orchestrator-Tests + Rust-Workspace-Tests
	node --test orchestrator/*.test.mjs
	cd kx && cargo test --workspace

check: ## Schnelle Qualitäts-Gates (wie CI demo.yml, ohne Rust)
	bash scripts/check.sh

lint: ## Wie check, plus cargo fmt --check + Rust-Tests
	bash scripts/check.sh --with-rust

e2e: ## E2E gegen das laufende Labor (vorher: make start)
	node orchestrator/e2e.mjs

graph: ## Architektur-Graph neu erzeugen (GUI, ohne Zusatz-Tools)
	node scripts/review-graph.mjs

crg: ## Optional: code-review-graph aktualisieren + Exporte (braucht die crg-CLI)
	cd kx && code-review-graph update
	cd kx && code-review-graph architecture > ../lab/run/crg/architecture.json
	cd kx && code-review-graph impact --files crates/kx-exploit/src/credential_stuff.rs > ../lab/run/crg/impact-credential-stuff.json

clean-lab: ## Labor-Container entfernen (Daten bleiben in lab/run/)
	-docker rm -f kx-lab-c2 kx-lab-patient0 kx-lab-target1 kx-lab-target2