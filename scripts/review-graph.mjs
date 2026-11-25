// @ts-check
/**
 * review-graph (Fallback für das code-review-graph-Addon): erzeugt den
 * Modul-Abhängigkeitsgraphen des kx-Workspace aus den Cargo-Manifesten und
 * schreibt ihn als public/architecture.json im GUI-Vertrag.
 *
 * Aufruf: node scripts/review-graph.mjs
 * Wenn die echte code-review-graph-CLI installiert ist, wird ihr Graph
 * zusätzlich unter lab/run/crg/ abgelegt (siehe SETUP_LOG.md).
 */
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const KX = path.join(ROOT, 'kx');

/** @param {string} p */
const read = (p) => fs.readFileSync(p, 'utf8');

const workspace = read(path.join(KX, 'Cargo.toml'));
const membersSection = workspace.split(/^\[/m).find((s) => s.startsWith('workspace]')) ?? '';
const members = [...new Set([...membersSection.matchAll(/"crates\/(kx-[a-z]+)"/g)].map((m) => m[1]))];

/** Gruppe für die GUI-Farben. @param {string} crate */
function groupOf(crate) {
  if (crate === 'kx-server') return 'server';
  if (crate === 'kx-agent') return 'agent';
  if (crate === 'kx-cli') return 'cli';
  return 'core';
}

const nodes = members.map((crate) => ({ id: crate, label: crate, group: groupOf(crate) }));
/** @type {{from: string, to: string}[]} */
const edges = [];
for (const crate of members) {
  const manifest = read(path.join(KX, 'crates', crate, 'Cargo.toml'));
  // Nur echte dependencies (keine dev-dependencies): Abschnittsweise lesen.
  const sections = manifest.split(/^\[/m);
  for (const section of sections) {
    if (!/^dependencies\]/.test(section)) continue;
    for (const dep of section.matchAll(/^(kx-[a-z]+)\s*=/gm)) {
      if (members.includes(dep[1]) && dep[1] !== crate) edges.push({ from: crate, to: dep[1] });
    }
  }
}

const graph = { ok: true, graph: { nodes, edges } };
fs.writeFileSync(path.join(ROOT, 'public', 'architecture.json'), JSON.stringify(graph, null, 2));
console.log(`architecture.json: ${nodes.length} Knoten, ${edges.length} Kanten`);