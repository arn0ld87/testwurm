// @ts-check
/**
 * Reine Logik des Testwurm-Orchestrators: Szenarien, Zustandsableitung aus
 * echten C2-Daten, Log-Parsing und Kontext-Kompression.
 *
 * Keine IO-Abhängigkeiten — alles hier ist unit-testbar (node --test).
 * Vertrag: docs/API_CONTRACT.md.
 */

/** @typedef {'ready'|'running'|'paused'|'completed'|'error_contained'} Phase */
/** @typedef {'info'|'warn'|'error'|'success'} LogLevel */
/** @typedef {{level: LogLevel, msg: string, detail?: string, t?: number}} LogEvent */
/** @typedef {{host_id: string, ip: string, hostname: string, os: string, status: string}} C2Host */
/** @typedef {{id: string, host_id: string, cred_type: string, username: string, source: string}} C2Secret */
/** @typedef {{id: string, host_id: string, command: string, status: string, result: string}} C2Task */

export const AGENT_HOST_ID = '172.31.99.10';
export const TARGET1_ID = '172.31.99.11';
export const TARGET2_ID = '172.31.99.12';

/** Die drei Demo-Szenarien. IDs sind Vertragsbestandteil der GUI. */
export const SCENARIOS = [
  {
    id: 'happy-path',
    name: 'Happy Path',
    description: 'Ein Ziel mit Default-Credentials – die komplette Kette läuft durch.',
    hosts: [TARGET1_ID],
    nodeCount: 9,
  },
  {
    id: 'error-recovery',
    name: 'Fehler & Recovery',
    description: 'Ziel mit starkem Passwort – der Exploit scheitert sauber, der Task-Kanal arbeitet weiter.',
    hosts: [TARGET2_ID],
    nodeCount: 9,
  },
  {
    id: 'full-traversal',
    name: 'Full Traversal',
    description: 'Beide Ziele, gemischte Ergebnisse, Task-Kanal inklusive.',
    hosts: [TARGET1_ID, TARGET2_ID],
    nodeCount: 9,
  },
];

/** Pipeline-Knoten des Wurms (Grid-Koordinaten für die GUI). */
export const NODE_DEFS = [
  { id: 'agent', label: 'patient0 · Agent', kind: 'module', x: 0, y: 1, detail: 'Der Wurm startet im Labor-Container patient0 (172.31.99.10).' },
  { id: 'register', label: 'C2-Registrierung', kind: 'module', x: 1, y: 1, detail: 'POST /api/register – der Agent meldet sich beim C2-Server.' },
  { id: 'loot', label: 'Lokale Beute', kind: 'module', x: 2, y: 0, detail: 'Extraktion von /etc/shadow, SSH-Keys und AWS-Credentials – nur im Container.' },
  { id: 'persist', label: 'Persistenz', kind: 'module', x: 2, y: 2, detail: 'systemd-Unit + Timer. Im Container ohne systemd wird der Fehler sauber abgefangen.' },
  { id: 'scan', label: 'Netz-Scan', kind: 'module', x: 3, y: 1, detail: 'TCP-Connect-Scan der Zielhosts über die 12 Standarddienste.' },
  { id: 't1', label: 'target1 · SSH', kind: 'target', x: 4, y: 0, detail: 'Labor-Ziel 172.31.99.11 – SSH mit Default-Credentials (root:root).' },
  { id: 't2', label: 'target2 · SSH', kind: 'target', x: 4, y: 2, detail: 'Labor-Ziel 172.31.99.12 – SSH mit starkem Passwort.' },
  { id: 'report', label: 'Beute-Meldung', kind: 'module', x: 5, y: 1, detail: 'Funde gehen an den C2 – mit Server-Schlüssel versiegelt.' },
  { id: 'tasks', label: 'Task-Kanal', kind: 'module', x: 6, y: 1, detail: 'Operator-Tasks werden geholt, im Container ausgeführt und zurückgemeldet.' },
];

export const EDGES = [
  { from: 'agent', to: 'register' },
  { from: 'register', to: 'loot' },
  { from: 'register', to: 'persist' },
  { from: 'loot', to: 'scan' },
  { from: 'persist', to: 'scan' },
  { from: 'scan', to: 't1' },
  { from: 'scan', to: 't2' },
  { from: 't1', to: 'report' },
  { from: 't2', to: 'report' },
  { from: 'report', to: 'tasks' },
];

const BANNER = {
  ready: 'Bereit',
  running: 'Läuft',
  paused: 'Pausiert',
  completed: 'Abgeschlossen',
  error_contained: 'Fehler abgefangen',
};

/**
 * Parst eine Zeile Agent-Log (tracing-Format) in ein LogEvent.
 * Format: `2026-11-25T00:58:00.123Z  INFO kx_agent::lauf: Nachricht`
 * @param {string} line
 * @returns {LogEvent|null}
 */
export function parseAgentLine(line) {
  const trimmed = line.replace(/\x1b\[[0-9;]*m/g, '').trim();
  if (!trimmed) return null;
  const m = trimmed.match(/^\S+\s+(TRACE|DEBUG|INFO|WARN|ERROR)\s+\S+:\s*(.*)$/);
  if (!m) return { level: 'info', msg: trimmed.slice(0, 120), detail: trimmed };
  const level = m[1] === 'ERROR' ? 'error' : m[1] === 'WARN' ? 'warn' : 'info';
  const full = m[2];
  return { level, msg: full.slice(0, 120), detail: full.length > 120 ? full : undefined };
}

/**
 * Kontext-Kompression nach contextmode-Prinzip: Meilenstein-Summaries plus
 * die letzten Rohzeilen statt des gesamten Logs. Die Ersparnis ist echt
 * gemessen (Zeichen/4 als Token-Schätzung), nicht behauptet.
 * @param {LogEvent[]} events
 * @param {{hosts: C2Host[], secrets: C2Secret[], tasks: C2Task[]}} snap
 */
export function compressContext(events, snap) {
  const rawChars = events.reduce((a, e) => a + e.msg.length + (e.detail ? e.detail.length : 0), 0);
  const summaries = buildSummaries(snap, events);
  const tail = events.slice(-8);
  const keptChars =
    summaries.join('\n').length +
    tail.reduce((a, e) => a + e.msg.length + (e.detail ? e.detail.length : 0), 0);
  const rawTokens = Math.ceil(rawChars / 4);
  const keptTokens = Math.ceil(keptChars / 4);
  const savedPct = rawTokens > 0 ? Math.max(0, Math.round((1 - keptTokens / rawTokens) * 100)) : 0;
  return { rawTokens, keptTokens, savedPct, summaries: summaries.length };
}

/**
 * Verdichtet den Lauf zu wenigen Faktenzeilen (der "komprimierte Kontext").
 * @param {{hosts: C2Host[], secrets: C2Secret[], tasks: C2Task[]}} snap
 * @param {LogEvent[]} events
 * @returns {string[]}
 */
export function buildSummaries(snap, events) {
  const out = [];
  const agent = snap.hosts.find((h) => h.status === 'agent');
  if (agent) out.push(`Agent registriert: ${agent.host_id}`);
  const localLoot = agent ? snap.secrets.filter((s) => s.host_id === agent.host_id) : [];
  if (localLoot.length > 0) {
    const types = [...new Set(localLoot.map((s) => s.cred_type))].join(', ');
    out.push(`Lokale Beute: ${localLoot.length} Stück (${types})`);
  }
  if (events.some((e) => e.msg.includes('Persistenz installiert'))) out.push('Persistenz: installiert');
  if (events.some((e) => e.msg.includes('Persistenz-Installation fehlgeschlagen')))
    out.push('Persistenz: fehlgeschlagen (kein systemd im Container) – abgefangen');
  const ports = events.filter((e) => e.msg.includes('Offener Port')).length;
  if (ports > 0) out.push(`Scan: ${ports} offene Ports gefunden`);
  for (const h of snap.hosts.filter((x) => x.status !== 'agent')) {
    out.push(`Ziel ${h.host_id}: ${h.status === 'compromised' ? 'kompromittiert' : 'erkannt, kein Zugriff'}`);
  }
  const done = snap.tasks.filter((t) => t.status === 'done').length;
  if (snap.tasks.length > 0) out.push(`Tasks: ${done}/${snap.tasks.length} ausgeführt`);
  return out;
}

/**
 * Leitet den vollständigen GUI-Zustand aus echten C2-Daten + Log ab.
 * @param {{scenarioId: string, phase: Phase, hosts: C2Host[], secrets: C2Secret[], tasks: C2Task[], events: LogEvent[], startedAt: number|null, now: number}} input
 */
export function deriveState(input) {
  const { scenarioId, phase, hosts, secrets, tasks, events, startedAt, now } = input;
  const scen = SCENARIOS.find((s) => s.id === scenarioId) ?? SCENARIOS[0];
  const agentHost = hosts.find((h) => h.status === 'agent');
  const agentSecrets = agentHost ? secrets.filter((s) => s.host_id === agentHost.host_id) : [];
  const persistOk = events.some((e) => e.msg.includes('Persistenz installiert'));
  const persistFail = events.some((e) => e.msg.includes('Persistenz-Installation fehlgeschlagen'));
  const scanStarted = events.some((e) => e.msg.includes('TCP-Scan'));
  const openPorts = events.filter((e) => e.msg.includes('Offener Port')).length;
  const targetHosts = hosts.filter((h) => h.status !== 'agent');
  const scanDone = targetHosts.length > 0 || openPorts > 0;

  /** @param {string} id @returns {string} */
  const targetStatus = (id) => {
    if (!scen.hosts.includes(id)) return 'skipped';
    const h = hosts.find((x) => x.host_id === id);
    if (h?.status === 'compromised') return 'passed';
    if (h?.status === 'discovered') return 'warning';
    return scanDone ? 'active' : 'pending';
  };

  const statusById = {
    agent: phase === 'ready' ? 'pending' : agentHost ? 'passed' : 'active',
    register: agentHost ? 'passed' : phase === 'ready' ? 'pending' : 'active',
    loot: agentSecrets.length > 0 ? 'passed' : agentHost ? 'active' : 'pending',
    persist: persistOk ? 'passed' : persistFail ? 'warning' : agentHost ? 'active' : 'pending',
    scan: scanDone ? 'passed' : scanStarted ? 'active' : agentHost ? 'active' : 'pending',
    t1: targetStatus(TARGET1_ID),
    t2: targetStatus(TARGET2_ID),
    report:
      scen.hosts.every((id) => hosts.some((h) => h.host_id === id))
        ? 'passed'
        : targetHosts.length > 0
          ? 'active'
          : 'pending',
    tasks:
      tasks.length === 0
        ? 'pending'
        : tasks.some((t) => t.status === 'failed')
          ? 'warning'
          : tasks.every((t) => t.status === 'done')
            ? 'passed'
            : 'active',
  };

  const nodes = NODE_DEFS.map((n) => ({
    ...n,
    status: /** @type {any} */ (statusById)[n.id] ?? 'pending',
    checks:
      n.id === 'loot'
        ? agentSecrets.length
        : n.id === 't1'
          ? secrets.filter((s) => s.host_id === TARGET1_ID).length
          : n.id === 't2'
            ? secrets.filter((s) => s.host_id === TARGET2_ID).length
            : n.id === 'tasks'
              ? tasks.filter((t) => t.status === 'done').length
              : 0,
  }));

  const path = nodes.filter((n) => n.status !== 'pending' && n.status !== 'skipped').map((n) => n.id);
  const errorsCaught = events.filter((e) => e.level === 'error').length;
  const recoveries = tasks.filter((t) => t.status === 'done').length;

  return {
    runStatus: phase,
    scenarioId: scen.id,
    scenarioName: scen.name,
    seed: 1337,
    tick: events.length,
    totalStepsPlanned: NODE_DEFS.length,
    worm: {
      currentNodeId: path[path.length - 1] ?? null,
      path,
      status: phase === 'running' ? 'moving' : phase === 'paused' ? 'checking' : 'idle',
    },
    nodes,
    edges: EDGES,
    log: events.slice(-200).map((e) => ({ t: e.t ?? 0, level: e.level, msg: e.msg, detail: e.detail })),
    context: compressContext(events, { hosts, secrets, tasks }),
    telemetry: {
      nodesVisited: path.length,
      checksRun: secrets.length + openPorts,
      errorsCaught,
      recoveries,
      durationMs: startedAt !== null ? Math.max(0, now - startedAt) : 0,
    },
    banner: BANNER[phase],
  };
}