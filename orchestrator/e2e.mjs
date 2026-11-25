// @ts-check
/** E2E-Test gegen den laufenden Orchestrator (echtes Labor). */
const BASE = 'http://127.0.0.1:8321';
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function api(path, body) {
  const res = await fetch(BASE + path, body ? {
    method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body),
  } : undefined);
  return res.json();
}

async function waitForReady() {
  for (let i = 0; i < 60; i++) {
    try {
      const r = await api('/api/state');
      if (r.ok) return r.state;
    } catch { /* noch nicht oben */ }
    await sleep(1000);
  }
  throw new Error('Orchestrator nicht erreichbar');
}

async function runScenario(scenarioId, maxWaitMs) {
  const reset = await api('/api/control', { action: 'reset', scenarioId });
  if (!reset.ok) throw new Error('Reset fehlgeschlagen: ' + JSON.stringify(reset));
  const start = await api('/api/control', { action: 'start' });
  if (!start.ok) throw new Error('Start fehlgeschlagen');
  const t0 = Date.now();
  let last = start.state;
  while (Date.now() - t0 < maxWaitMs) {
    await sleep(1000);
    const r = await api('/api/state');
    last = r.state;
    if (last.runStatus === 'completed' || last.runStatus === 'error_contained') break;
  }
  return last;
}

const byId = (s) => Object.fromEntries(s.nodes.map((n) => [n.id, n.status]));

try {
  const ready = await waitForReady();
  console.log('READY banner=', ready.banner, 'scenario=', ready.scenarioId);

  const happy = await runScenario('happy-path', 120000);
  const h = byId(happy);
  console.log('HAPPY status=', happy.runStatus, 'banner=', happy.banner);
  console.log('HAPPY nodes=', JSON.stringify(h));
  console.log('HAPPY context=', JSON.stringify(happy.context), 'telemetry=', JSON.stringify(happy.telemetry));
  console.log('HAPPY logtail=', JSON.stringify(happy.log.slice(-6).map((l) => l.msg)));
  const happyOk = happy.runStatus === 'completed' && h.register === 'passed' && h.loot === 'passed'
    && h.t1 === 'passed' && h.report === 'passed';
  console.log(happyOk ? 'HAPPY_OK' : 'HAPPY_FAIL');

  const err = await runScenario('error-recovery', 120000);
  const e = byId(err);
  console.log('ERROR status=', err.runStatus, 'nodes=', JSON.stringify(e));
  console.log('ERROR context=', JSON.stringify(err.context), 'telemetry=', JSON.stringify(err.telemetry));
  console.log('ERROR logtail=', JSON.stringify(err.log.slice(-6).map((l) => l.msg)));
  const errOk = err.runStatus === 'completed' && e.t2 === 'warning' && e.t1 === 'skipped' && e.tasks === 'passed';
  console.log(errOk ? 'ERROR_OK' : 'ERROR_FAIL');

  const full = await runScenario('full-traversal', 150000);
  const f = byId(full);
  console.log('FULL status=', full.runStatus, 'nodes=', JSON.stringify(f));
  const fullOk = full.runStatus === 'completed' && f.t1 === 'passed' && f.t2 === 'warning';
  console.log(fullOk ? 'FULL_OK' : 'FULL_FAIL');

  const reset = await api('/api/control', { action: 'reset', scenarioId: 'happy-path' });
  console.log('RESET banner=', reset.state.banner, 'nodesPending=', reset.state.nodes.every((n) => n.status === 'pending' || n.status === 'skipped'));

  const arch = await (await fetch(BASE + '/architecture.json')).json();
  console.log('ARCH ok=', arch.ok, 'nodes=', arch.graph.nodes.length, 'edges=', arch.graph.edges.length);
  const html = await (await fetch(BASE + '/')).text();
  console.log('GUI html=', html.includes('Live-Labor') ? 'OK' : 'FAIL');

  console.log(happyOk && errOk && fullOk ? 'E2E_PASS' : 'E2E_FAIL');
  process.exit(happyOk && errOk && fullOk ? 0 : 1);
} catch (e) {
  console.error('E2E_ERROR', e);
  process.exit(1);
}