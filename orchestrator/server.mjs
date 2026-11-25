// @ts-check
/**
 * Testwurm-Orchestrator: steuert das ECHTE kx-System im isolierten Docker-Labor
 * und bedient die GUI unter dem Vertrag aus docs/API_CONTRACT.md.
 *
 * Aufbau:
 *   - kx-server (C2) als Container kx-lab-c2 im Labor-Netz (172.31.99.2);
 *     Host-Firewall blockiert Container→Host, deshalb kein Host-Prozess
 *   - kx-lab-target1/2: SSH-Zielcontainer (kontrollierte Credentials)
 *   - kx-lab-patient0: Container, in dem der echte kx-Agent läuft
 *
 * Sicherheitsgrenzen: Der Agent läuft NUR im Container. Alle Ziele liegen im
 * isolierten Docker-Netz kx-lab. Keine Zugriffe auf Host-Secrets, kein
 * externes Netz. Labor-Container werden bei Reset/Shutdown entfernt.
 *
 * Keine npm-Abhängigkeiten — nur Node-Built-ins (>= 18).
 */

import http from 'node:http';
import https from 'node:https';
import fs from 'node:fs';
import path from 'node:path';
import net from 'node:net';
import crypto from 'node:crypto';
import { spawn, spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import {
  SCENARIOS, AGENT_HOST_ID, TARGET1_ID, TARGET2_ID, deriveState, parseAgentLine,
} from './lib.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const RUN = path.join(ROOT, 'lab', 'run');
const PUBLIC = path.join(ROOT, 'public');
const DIST = path.join(ROOT, 'kx', 'dist');
const NET_NAME = 'kx-lab';
const C2_IP = '172.31.99.2';
const C2_PORT = 18443;
const CN = 'kx-c2.lab';
const GUI_PORT = 8321;

/** @type {import('./lib.mjs').Phase} */
let phase = 'ready';
let scenarioId = 'happy-path';
/** @type {import('./lib.mjs').LogEvent[]} */
let events = [];
/** @type {number|null} */
let startedAt = null;
/** @type {{hosts: import('./lib.mjs').C2Host[], secrets: import('./lib.mjs').C2Secret[], tasks: import('./lib.mjs').C2Task[]}} */
let snap = { hosts: [], secrets: [], tasks: [] };
/** @type {ChildProcess|null} */
let logProc = null;
let serverGen = 0;
let token = '';
let certPem = '';
let connectionLost = false;
let stepTimer = null;
let runCounter = 0;

// ---------------------------------------------------------------- Helpers

/** @param {string} msg @param {import('./lib.mjs').LogLevel} [level] */
function logEvent(msg, level = 'info') {
  events.push({ t: Date.now(), level, msg: msg.slice(0, 120), detail: msg.length > 120 ? msg : undefined });
  if (events.length > 600) events = events.slice(-600);
}

/**
 * Führt ein Kommando aus und liefert stdout/stderr + Exitcode.
 * @param {string} cmd @param {string[]} args @param {{timeout?: number, cwd?: string}} [opts]
 * @returns {Promise<{code: number, stdout: string, stderr: string}>}
 */
function exec(cmd, args, opts = {}) {
  return new Promise((resolve) => {
    const child = spawn(cmd, args, { cwd: opts.cwd ?? ROOT });
    let stdout = '';
    let stderr = '';
    const timer = setTimeout(() => child.kill('SIGKILL'), opts.timeout ?? 30000);
    child.stdout.on('data', (d) => { stdout += d.toString(); });
    child.stderr.on('data', (d) => { stderr += d.toString(); });
    child.on('error', (e) => { clearTimeout(timer); resolve({ code: 1, stdout, stderr: String(e) }); });
    child.on('close', (code) => { clearTimeout(timer); resolve({ code: code ?? 1, stdout, stderr }); });
  });
}

/** @param {string[]} args @param {number} [timeout] */
async function docker(args, timeout = 30000) {
  const res = await exec('docker', args, { timeout });
  if (res.code !== 0) throw new Error(`docker ${args[0]} fehlgeschlagen: ${res.stderr.trim().slice(0, 300)}`);
  return res.stdout.trim();
}

/** @param {number} ms */
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

/** Wartet, bis ein TCP-Port erreichbar ist. @param {string} host @param {number} port @param {number} tries */
async function waitForPort(host, port, tries = 40) {
  for (let i = 0; i < tries; i++) {
    const ok = await new Promise((resolve) => {
      const s = net.connect({ host, port, timeout: 1000 });
      s.once('connect', () => { s.destroy(); resolve(true); });
      s.once('error', () => resolve(false));
      s.once('timeout', () => { s.destroy(); resolve(false); });
    });
    if (ok) return;
    await sleep(500);
  }
  throw new Error(`${host}:${port} nach ${tries} Versuchen nicht erreichbar`);
}

// ---------------------------------------------------------------- C2-Client

/**
 * HTTPS-Request an den C2 mit echtem Zertifikats-Pinning (CA = exportiertes
 * Server-Zertifikat, SNI = CN). @param {string} method @param {string} p @param {unknown} [body]
 */
function c2Request(method, p, body) {
  return new Promise((resolve, reject) => {
    const data = body ? JSON.stringify(body) : null;
    const req = https.request({
      host: C2_IP, port: C2_PORT, servername: CN, ca: certPem || undefined,
      rejectUnauthorized: !!certPem, method, path: p,
      headers: {
        Authorization: `Bearer ${token}`,
        ...(data ? { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(data) } : {}),
      },
      timeout: 5000,
    }, (res) => {
      let raw = '';
      res.on('data', (d) => { raw += d; });
      res.on('end', () => {
        try { resolve({ status: res.statusCode ?? 0, json: raw ? JSON.parse(raw) : null }); }
        catch { resolve({ status: res.statusCode ?? 0, json: null }); }
      });
    });
    req.on('error', reject);
    req.on('timeout', () => req.destroy(new Error('C2-Timeout')));
    if (data) req.write(data);
    req.end();
  });
}

/** Holt den aktuellen C2-Stand; Secrets werden OHNE Passwort-Werte übernommen. */
async function pollC2() {
  const [h, s, t] = await Promise.all([
    c2Request('GET', '/api/hosts'),
    c2Request('GET', '/api/secrets'),
    c2Request('GET', '/api/tasks'),
  ]);
  /** @param {any} r */
  const arr = (r) => (r.status === 200 && Array.isArray(r.json) ? r.json : []);
  snap = {
    hosts: arr(h),
    secrets: arr(s).map((x) => ({ id: x.id, host_id: x.host_id, cred_type: x.cred_type, username: x.username, source: x.source })),
    tasks: arr(t),
  };
  if (connectionLost) { connectionLost = false; logEvent('Verbindung zum C2 wiederhergestellt', 'success'); }
}

// ---------------------------------------------------------------- Lebenszyklus

/** Startet den C2-Server als Container im Labor-Netz (falls nötig) und exportiert das Zertifikat.
 *  Container statt Host-Prozess: die Host-Firewall (ufw) blockiert Container→Host,
 *  Container→Container im Labor-Netz ist frei. */
async function ensureServer() {
  const running = await exec('docker', ['inspect', '-f', '{{.State.Running}}', 'kx-lab-c2']);
  if (running.code === 0 && running.stdout.trim() === 'true') return;
  fs.mkdirSync(RUN, { recursive: true });
  const gen = ++serverGen;
  await exec('docker', ['rm', '-f', 'kx-lab-c2']);
  await docker(['run', '-d', '--name', 'kx-lab-c2', '--network', NET_NAME, '--ip', C2_IP,
    '-e', `KX_SERVER_TOKEN=${token}`,
    '-v', `${path.join(DIST, 'kx-server')}:/opt/kx/kx-server:ro`,
    '-v', `${RUN}:/data`,
    '--entrypoint', '/opt/kx/kx-server', '--restart', 'no',
    'kx-lab-patient0',
    '--host', C2_IP, '--port', String(C2_PORT), '--db', '/data/kx.db', '--cn', CN]);
  docker(['wait', 'kx-lab-c2'], 3600000).then((codeStr) => {
    if (gen !== serverGen || phase === 'ready') return;
    const code = parseInt(codeStr, 10);
    if (code !== 0) {
      logEvent(`C2-Server unerwartet beendet (Code ${code})`, 'error');
      phase = 'error_contained';
    }
  }).catch(() => {});
  await waitForPort(C2_IP, C2_PORT);
  const pem = await exec('bash', ['-c',
    `openssl s_client -connect ${C2_IP}:${C2_PORT} -servername ${CN} </dev/null 2>/dev/null | openssl x509 -outform PEM`],
    { timeout: 15000 });
  if (!pem.stdout.includes('BEGIN CERTIFICATE')) throw new Error('Zertifikatsexport fehlgeschlagen');
  certPem = pem.stdout;
  fs.writeFileSync(path.join(RUN, 'server.pem'), certPem);
  const check = await c2Request('GET', '/api/hosts');
  if (check.status !== 200) throw new Error(`C2-Authentifizierung fehlgeschlagen (HTTP ${check.status})`);
  logEvent(`C2-Server bereit: https://${CN}:${C2_PORT} (Labor-Bridge ${C2_IP})`, 'success');
}

/** Erzeugt die Zielcontainer frisch (Reset-Zustand, keine Persistenzreste). */
async function ensureTargets() {
  const target2Pw = crypto.randomBytes(12).toString('hex');
  for (const [name, ip, pw] of /** @type {const} */ ([
    ['kx-lab-target1', TARGET1_ID, 'root'],
    ['kx-lab-target2', TARGET2_ID, target2Pw],
  ])) {
    await exec('docker', ['rm', '-f', name]);
    await docker(['run', '-d', '--name', name, '--network', NET_NAME, '--ip', ip,
      '--add-host', `${CN}:${C2_IP}`, '-e', `ROOT_PW=${pw}`, '--restart', 'no', 'kx-lab-target']);
    await waitForPort(ip, 22);
  }
  logEvent('Labor-Ziele bereit: target1 (Default-Credentials), target2 (starkes Passwort)', 'success');
}

/** Startet einen echten Agenten-Lauf im patient0-Container. */
async function startRun() {
  const scen = SCENARIOS.find((s) => s.id === scenarioId) ?? SCENARIOS[0];
  const runId = ++runCounter;
  if (logProc) { logProc.kill('SIGKILL'); logProc = null; }
  // Frischer Lauf = frische Daten: C2 und DB zurücksetzen. Sonst meldet der
  // nächste Poll Registration, Beute und Tasks des Vorlaufs als Ergebnisse
  // dieses Laufs (und alte Tasks zählen in die Recovery-Statistik hinein).
  snap = { hosts: [], secrets: [], tasks: [] };
  serverGen++;
  await exec('docker', ['rm', '-f', 'kx-lab-c2']);
  for (const f of ['kx.db', 'kx.db-wal', 'kx.db-shm', 'kx-server.crt', 'kx-server.key', 'kx-server.crt.tmp', 'kx-server.key.tmp']) {
    try { fs.unlinkSync(path.join(RUN, f)); } catch { /* egal */ }
  }
  await ensureServer();
  await ensureTargets();
  events = events.slice(-2);
  startedAt = Date.now();

  // Operator-Task wird angelegt, sobald der Agent registriert ist (der C2
  // lehnt Tasks für unbekannte Hosts ab). Der Agent holt ihn am Ende seines
  // Laufs. Nur Befehle, die im Labor-Container laufen.
  if (scen.id !== 'happy-path') {
    (async () => {
      for (let i = 0; i < 60 && runId === runCounter; i++) {
        await sleep(500);
        try {
          const h = await c2Request('GET', '/api/hosts');
          if (h.status === 200 && Array.isArray(h.json) && h.json.some((x) => x.host_id === AGENT_HOST_ID)) {
            const t = await c2Request('POST', '/api/tasks/new', { host_id: AGENT_HOST_ID, command: 'uname -a && id' });
            if (t.status === 201) logEvent('Operator-Task angelegt: uname -a && id (wartet auf den Agenten)');
            else logEvent(`Task-Anlage fehlgeschlagen (HTTP ${t.status})`, 'warn');
            return;
          }
        } catch { /* Reconnect beim nächsten Versuch */ }
      }
    })();
  }

  await exec('docker', ['rm', '-f', 'kx-lab-patient0']);
  const pubKeyPath = path.join(RUN, 'server-pub.json');
  const sealed = fs.existsSync(pubKeyPath);
  const args = ['run', '-d', '--name', 'kx-lab-patient0', '--network', NET_NAME,
    '--ip', AGENT_HOST_ID, '--add-host', `${CN}:${C2_IP}`,
    '-e', `KX_C2_TOKEN=${token}`,
    '-v', `${path.join(DIST, 'kx-agent')}:/opt/kx/kx-agent:ro`,
    '-v', `${path.join(ROOT, 'kx', 'assets')}:/opt/kx/assets:ro`,
    '-v', `${path.join(RUN, 'server.pem')}:/opt/kx/run/server.pem:ro`,
    '--restart', 'no'];
  if (sealed) args.push('-v', `${pubKeyPath}:/opt/kx/run/server-pub.json:ro`);
  args.push('kx-lab-patient0',
    '--server', `https://${CN}:${C2_PORT}`,
    '--server-cert', '/opt/kx/run/server.pem',
    '--iface', 'eth0', '--own-ip', AGENT_HOST_ID,
    '--start', TARGET1_ID, '--end', TARGET2_ID,
    '--hosts', scen.hosts.join(','),
    '--relay-script', '/opt/kx/assets/smbrelayx.py');
  if (sealed) args.push('--server-key', '/opt/kx/run/server-pub.json');
  else logEvent('Hinweis: kein Server-Schlüssel – Beute geht unversiegelt (nur TLS) an den C2', 'warn');
  await docker(args);

  phase = 'running';
  logEvent(`Agent gestartet im Labor-Container patient0 – Szenario "${scen.name}"`, 'success');

  // Live-Log des Agenten einsammeln.
  logProc = spawn('docker', ['logs', '-f', 'kx-lab-patient0']);
  const onLine = (/** @type {string} */ line) => {
    const ev = parseAgentLine(line);
    if (ev) { events.push({ ...ev, t: Date.now() }); if (events.length > 600) events = events.slice(-600); }
  };
  let buf = '';
  const onData = (/** @type {Buffer} */ d) => {
    buf += d.toString();
    const lines = buf.split('\n');
    buf = lines.pop() ?? '';
    lines.forEach(onLine);
  };
  logProc.stdout.on('data', onData);
  logProc.stderr.on('data', onData);

  // Exit des Containers beobachten (Einmal-Lauf des Agenten).
  docker(['wait', 'kx-lab-patient0'], 600000).then((codeStr) => {
    if (runId !== runCounter) return;
    const code = parseInt(codeStr, 10);
    if (code === 0) {
      phase = 'completed';
      logEvent('Agent-Lauf abgeschlossen – alle Meldungen beim C2', 'success');
    } else {
      phase = 'error_contained';
      logEvent(`Agent-Lauf endete mit Code ${code} – Zustand bleibt bedienbar`, 'error');
    }
    pollC2().catch(() => {});
  }).catch((e) => {
    if (runId !== runCounter) return;
    phase = 'error_contained';
    logEvent(`Lauf-Beobachtung fehlgeschlagen: ${e.message}`, 'error');
  });
}

/** Pause: friert den Container ein (cgroup freezer) – echter Stopp, kein Fake. */
async function pauseRun() {
  if (phase !== 'running') return;
  await docker(['pause', 'kx-lab-patient0']);
  phase = 'paused';
  logEvent('Lauf pausiert (Container eingefroren)');
}

/** Einzelschritt: 700 ms laufen lassen, dann wieder einfrieren. */
async function stepRun() {
  if (phase === 'ready' || phase === 'completed' || phase === 'error_contained') {
    await startRun();
  } else if (phase === 'paused') {
    await docker(['unpause', 'kx-lab-patient0']);
    phase = 'running';
  }
  if (stepTimer) clearTimeout(stepTimer);
  stepTimer = setTimeout(() => {
    if (phase === 'running') pauseRun().catch((e) => logEvent(`Pause fehlgeschlagen: ${e.message}`, 'error'));
  }, 700);
}

/** Reset: Agent weg, DB leer, Ziele frisch, Server neu – sauberer Ausgangszustand. */
async function resetDemo(newScenarioId) {
  runCounter++;
  if (stepTimer) { clearTimeout(stepTimer); stepTimer = null; }
  if (logProc) { logProc.kill('SIGKILL'); logProc = null; }
  await exec('docker', ['rm', '-f', 'kx-lab-patient0']);
  serverGen++;
  await exec('docker', ['rm', '-f', 'kx-lab-c2']);
  await sleep(300);
  for (const f of ['kx.db', 'kx.db-wal', 'kx.db-shm', 'kx-server.crt', 'kx-server.key', 'kx-server.crt.tmp', 'kx-server.key.tmp']) {
    try { fs.unlinkSync(path.join(RUN, f)); } catch { /* egal */ }
  }
  if (typeof newScenarioId === 'string' && SCENARIOS.some((s) => s.id === newScenarioId)) {
    scenarioId = newScenarioId;
  }
  phase = 'ready';
  startedAt = null;
  snap = { hosts: [], secrets: [], tasks: [] };
  events = [];
  await ensureServer();
  await ensureTargets();
  logEvent(`Demo zurückgesetzt – Szenario "${SCENARIOS.find((s) => s.id === scenarioId)?.name}" bereit`);
}

// ---------------------------------------------------------------- HTTP-API

/** Lebenszyklus-Operationen strikt serialisieren: parallele Klicks (Start
 *  doppelt, Szenario-Wahl + Start) dürfen sich nicht in die Container-
 *  Operationen funken. Jede Aktion wartet auf die vorherige; der Zustand
 *  wird erst nach Abschluss der laufenden Aktion neu bewertet. */
let opChain = Promise.resolve();
/** @param {() => Promise<void>} op */
function serialize(op) {
  const run = opChain.then(op, op);
  opChain = run.then(() => {}, () => {});
  return run;
}

/** @returns {ReturnType<typeof deriveState>} */
function currentState() {
  return deriveState({ scenarioId, phase, hosts: snap.hosts, secrets: snap.secrets, tasks: snap.tasks, events, startedAt, now: Date.now() });
}

const MIME = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8', '.json': 'application/json; charset=utf-8', '.svg': 'image/svg+xml' };

/** @param {http.ServerResponse} res @param {number} code @param {unknown} obj */
function sendJson(res, code, obj) {
  const body = JSON.stringify(obj);
  res.writeHead(code, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' });
  res.end(body);
}

const httpServer = http.createServer(async (req, res) => {
  try {
    const url = new URL(req.url ?? '/', 'http://localhost');
    if (url.pathname === '/api/state' && req.method === 'GET') {
      return sendJson(res, 200, { ok: true, state: currentState() });
    }
    if (url.pathname === '/api/scenarios' && req.method === 'GET') {
      return sendJson(res, 200, { ok: true, scenarios: SCENARIOS.map(({ id, name, description, nodeCount }) => ({ id, name, description, nodeCount })) });
    }
    if (url.pathname === '/api/control' && req.method === 'POST') {
      let raw = '';
      for await (const chunk of req) { raw += chunk; if (raw.length > 10240) break; }
      /** @type {any} */
      let body;
      try { body = JSON.parse(raw || '{}'); } catch { return sendJson(res, 400, { ok: false, error: 'Ungültiges JSON' }); }
      const action = body.action;
      if (!['start', 'pause', 'step', 'reset'].includes(action)) {
        return sendJson(res, 400, { ok: false, error: 'Unbekannte Aktion' });
      }
      try {
        await serialize(async () => {
          if (action === 'start') {
            if (phase === 'paused') { await docker(['unpause', 'kx-lab-patient0']); phase = 'running'; logEvent('Lauf fortgesetzt'); }
            else if (phase !== 'running') await startRun();
          } else if (action === 'pause') await pauseRun();
          else if (action === 'step') await stepRun();
          else if (action === 'reset') await resetDemo(body.scenarioId);
        });
      } catch (e) {
        phase = 'error_contained';
        logEvent(`Aktion "${action}" fehlgeschlagen: ${e instanceof Error ? e.message : String(e)}`, 'error');
      }
      return sendJson(res, 200, { ok: true, state: currentState() });
    }
    // Statische GUI-Dateien (kein Directory-Traversal).
    let filePath = path.normalize(path.join(PUBLIC, url.pathname === '/' ? 'index.html' : url.pathname));
    if (!filePath.startsWith(PUBLIC)) { res.writeHead(403); return res.end(); }
    if (fs.existsSync(filePath) && fs.statSync(filePath).isFile()) {
      res.writeHead(200, { 'Content-Type': MIME[path.extname(filePath)] ?? 'application/octet-stream', 'Cache-Control': 'no-store' });
      return fs.createReadStream(filePath).pipe(res);
    }
    res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' });
    res.end('Nicht gefunden');
  } catch (e) {
    sendJson(res, 500, { ok: false, error: e instanceof Error ? e.message : 'Interner Fehler' });
  }
});

// ---------------------------------------------------------------- Start

async function main() {
  fs.mkdirSync(RUN, { recursive: true });
  for (const bin of ['kx-server', 'kx-agent']) {
    if (!fs.existsSync(path.join(DIST, bin))) {
      console.error(`FEHLER: ${DIST}/${bin} fehlt. Bitte zuerst ./start.sh ausführen (baut automatisch).`);
      process.exit(1);
    }
  }
  const netCheck = await exec('docker', ['network', 'inspect', NET_NAME]);
  const imgCheck = await exec('docker', ['image', 'inspect', 'kx-lab-target', 'kx-lab-patient0']);
  if (netCheck.code !== 0 || imgCheck.code !== 0) {
    console.log('Labor-Setup läuft (Netz + Images)…');
    const setup = spawnSync('bash', [path.join(ROOT, 'lab', 'setup.sh')], { stdio: 'inherit' });
    if (setup.status !== 0) { console.error('Labor-Setup fehlgeschlagen.'); process.exit(1); }
  }
  const tokenPath = path.join(RUN, 'token.txt');
  if (fs.existsSync(tokenPath)) token = fs.readFileSync(tokenPath, 'utf8').trim();
  if (!token) {
    token = crypto.randomBytes(32).toString('hex');
    fs.writeFileSync(tokenPath, token, { mode: 0o600 });
  }
  await ensureServer();
  await ensureTargets();
  logEvent('Labor bereit – Start drücken, um den echten Wurm laufen zu lassen', 'success');

  // C2-Polling (nur wenn ein Lauf existiert/hat existiert).
  setInterval(() => {
    if (phase !== 'ready') {
      pollC2().catch(() => {
        if (!connectionLost) { connectionLost = true; logEvent('C2-Polling fehlgeschlagen – Reconnect läuft', 'warn'); }
      });
    }
  }, 500);

  // GUI-Port suchen (8321, dann Ausweichports).
  let port = GUI_PORT;
  for (;;) {
    const ok = await new Promise((resolve) => {
      httpServer.once('error', () => resolve(false));
      httpServer.listen(port, '127.0.0.1', () => resolve(true));
    });
    if (ok) break;
    httpServer.removeAllListeners('error');
    port++;
    if (port > GUI_PORT + 9) { console.error('Kein freier GUI-Port gefunden.'); process.exit(1); }
  }
  const url = `http://127.0.0.1:${port}`;
  console.log(`\n  Testwurm-GUI: ${url}\n  C2 (Labor):   https://${CN}:${C2_PORT}\n  Strg+C beendet Server und räumt Labor-Container ab.\n`);
  if (process.env.NO_OPEN !== '1') {
    const opener = process.platform === 'darwin' ? 'open' : 'xdg-open';
    spawn(opener, [url], { detached: true, stdio: 'ignore' }).on('error', () => {});
  }
}

async function shutdown() {
  console.log('\nRäume Labor auf…');
  if (logProc) logProc.kill('SIGKILL');
  serverGen++;
  await exec('docker', ['rm', '-f', 'kx-lab-patient0', 'kx-lab-target1', 'kx-lab-target2', 'kx-lab-c2'], { timeout: 20000 });
  httpServer.close();
  process.exit(0);
}
process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);

main().catch((e) => { console.error('Start fehlgeschlagen:', e); process.exit(1); });