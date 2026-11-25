// @ts-check
/** Tests der Orchestrator-Logik: node --test orchestrator/*.test.mjs */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  SCENARIOS, NODE_DEFS, AGENT_HOST_ID, TARGET1_ID, TARGET2_ID,
  parseAgentLine, deriveState, compressContext, buildSummaries,
} from './lib.mjs';

const base = {
  scenarioId: 'happy-path',
  phase: /** @type {const} */ ('ready'),
  hosts: [], secrets: [], tasks: [], events: [],
  startedAt: null, now: 1000,
};

test('Szenarien: feste IDs, beide Ziele im Full Traversal', () => {
  assert.deepEqual(SCENARIOS.map((s) => s.id), ['happy-path', 'error-recovery', 'full-traversal']);
  assert.deepEqual(SCENARIOS[2].hosts, [TARGET1_ID, TARGET2_ID]);
});

test('parseAgentLine: tracing-Format wird korrekt zerlegt', () => {
  const ev = parseAgentLine('2026-11-25T00:58:00.123456Z  WARN kx_agent::lauf: Persistenz-Installation fehlgeschlagen: systemctl fehlt');
  assert.equal(ev?.level, 'warn');
  assert.ok(ev?.msg.startsWith('Persistenz-Installation fehlgeschlagen'));
  assert.equal(parseAgentLine('   '), null);
  const plain = parseAgentLine('irgendeine Zeile ohne Format');
  assert.equal(plain?.level, 'info');
});

test('Ready-Zustand: Banner Bereit, alles pending, keine Ersparnis', () => {
  const s = deriveState(base);
  assert.equal(s.runStatus, 'ready');
  assert.equal(s.banner, 'Bereit');
  assert.ok(s.nodes.every((n) => n.status === 'pending' || n.status === 'skipped'));
  assert.equal(s.context.savedPct, 0);
  assert.equal(s.worm.path.length, 0);
});

test('Happy Path: registrierter Agent + Beute + kompromittiertes Ziel → grüne Kette', () => {
  const s = deriveState({
    ...base,
    phase: 'completed',
    startedAt: 0,
    now: 5000,
    hosts: [
      { host_id: AGENT_HOST_ID, ip: AGENT_HOST_ID, hostname: 'patient0', os: 'linux', status: 'agent' },
      { host_id: TARGET1_ID, ip: TARGET1_ID, hostname: 'target1', os: 'linux', status: 'compromised' },
    ],
    secrets: [
      { id: '1', host_id: AGENT_HOST_ID, cred_type: 'shadow', username: 'root', source: '/etc/shadow' },
      { id: '2', host_id: TARGET1_ID, cred_type: 'password', username: 'root', source: 'ssh' },
    ],
    events: [
      { level: 'info', msg: 'TCP-Scan auf 1 Hosts' },
      { level: 'info', msg: 'Offener Port 22 auf 172.31.99.11 (ssh)' },
      { level: 'error', msg: 'Persistenz-Installation fehlgeschlagen: systemctl fehlt' },
    ],
  });
  const byId = Object.fromEntries(s.nodes.map((n) => [n.id, n.status]));
  assert.equal(byId.register, 'passed');
  assert.equal(byId.loot, 'passed');
  assert.equal(byId.persist, 'warning'); // eine fehlgeschlagene Persistenz ist ein Warning, kein Erfolg
  assert.equal(byId.t1, 'passed');
  assert.equal(byId.t2, 'skipped');
  assert.equal(byId.report, 'passed');
  assert.equal(s.banner, 'Abgeschlossen');
  assert.equal(s.telemetry.errorsCaught, 1);
  assert.equal(s.telemetry.durationMs, 5000);
  assert.ok(s.worm.path.includes('t1'));
});

test('Fehler & Recovery: entdecktes Ziel ohne Zugriff → warning, Task done → passed', () => {
  const s = deriveState({
    ...base,
    scenarioId: 'error-recovery',
    phase: 'completed',
    hosts: [
      { host_id: AGENT_HOST_ID, ip: AGENT_HOST_ID, hostname: 'patient0', os: 'linux', status: 'agent' },
      { host_id: TARGET2_ID, ip: TARGET2_ID, hostname: 'target2', os: 'linux', status: 'discovered' },
    ],
    tasks: [{ id: 't1', host_id: AGENT_HOST_ID, command: 'uname -a', status: 'done', result: 'Linux' }],
    events: [{ level: 'info', msg: 'TCP-Scan auf 1 Hosts' }],
  });
  const byId = Object.fromEntries(s.nodes.map((n) => [n.id, n.status]));
  assert.equal(byId.t1, 'skipped');
  assert.equal(byId.t2, 'warning');
  assert.equal(byId.tasks, 'passed');
  assert.equal(s.telemetry.recoveries, 1);
});

test('Kontext-Kompression: Ersparnis steigt mit der Log-Länge und ist echt berechnet', () => {
  const events = Array.from({ length: 100 }, (_, i) => ({
    level: /** @type {const} */ ('info'),
    msg: `Schritt ${i}: Detailprüfung des Knotens mit längerem Text`,
    detail: `Rohzeile ${i} mit zusätzlichen Informationen, die niemand dauerhaft lesen muss`,
  }));
  const snap = { hosts: [], secrets: [], tasks: [] };
  const c = compressContext(events, snap);
  assert.ok(c.rawTokens > c.keptTokens);
  assert.ok(c.savedPct > 50, `savedPct=${c.savedPct}`);
  assert.equal(c.summaries, buildSummaries(snap, events).length);
});

test('Alle Knoten haben Grid-Koordinaten und eindeutige IDs', () => {
  const ids = new Set(NODE_DEFS.map((n) => n.id));
  assert.equal(ids.size, NODE_DEFS.length);
  for (const n of NODE_DEFS) {
    assert.ok(Number.isInteger(n.x) && n.x >= 0);
    assert.ok(Number.isInteger(n.y) && n.y >= 0);
  }
});