// Testwurm GUI – Vanilla JS
(function() {
  'use strict';

  // Konfiguration
  const API_BASE = window.location.origin;
  const POLL_INTERVAL = 400;
  const MAX_LOG_ENTRIES = 80;

  // State
  let state = null;
  let pollTimer = null;
  let selectedScenario = 'happy-path';
  let activeTab = 'simulation'; // 'simulation' | 'architecture'
  let architectureData = null;
  let logAutoScroll = true;
  let errorBannerTimeout = null;

  // DOM-Elemente
  const elements = {
    statusBanner: document.getElementById('status-banner'),
    errorBanner: document.getElementById('error-banner'),
    errorBannerText: document.getElementById('error-banner-text'),
    btnStart: document.getElementById('btn-start'),
    btnPause: document.getElementById('btn-pause'),
    btnStep: document.getElementById('btn-step'),
    btnReset: document.getElementById('btn-reset'),
    tabSimulation: document.getElementById('tab-simulation'),
    tabArchitecture: document.getElementById('tab-architecture'),
    graphSvg: document.getElementById('graph-svg'),
    graphContainer: document.getElementById('graph-container'),
    savedPct: document.getElementById('saved-pct'),
    rawTokens: document.getElementById('raw-tokens'),
    keptTokens: document.getElementById('kept-tokens'),
    summaries: document.getElementById('summaries'),
    nodesVisited: document.getElementById('nodes-visited'),
    checksRun: document.getElementById('checks-run'),
    errorsCaught: document.getElementById('errors-caught'),
    recoveries: document.getElementById('recoveries'),
    logContainer: document.getElementById('log-container')
  };

  // Fehlerresistenz
  function showErrorBanner(message) {
    elements.errorBannerText.textContent = message;
    elements.errorBanner.classList.remove('hidden');
    if (errorBannerTimeout) clearTimeout(errorBannerTimeout);
    errorBannerTimeout = setTimeout(() => {
      elements.errorBanner.classList.add('hidden');
    }, 5000);
  }

  function hideErrorBanner() {
    elements.errorBanner.classList.add('hidden');
  }

  window.onerror = function(msg, url, line, col, error) {
    showErrorBanner('Fehler abgefangen – Oberfläche bleibt bedienbar');
    addLogEntry({ t: Date.now(), level: 'error', msg: String(msg), detail: error ? error.stack : '' });
    return true;
  };

  window.onunhandledrejection = function(event) {
    showErrorBanner('Fehler abgefangen – Oberfläche bleibt bedienbar');
    addLogEntry({ t: Date.now(), level: 'error', msg: 'Promise-Fehler', detail: event.reason ? String(event.reason) : '' });
  };

  // API-Funktionen
  async function fetchState() {
    try {
      const response = await fetch(API_BASE + '/api/state');
      if (!response.ok) throw new Error('HTTP ' + response.status);
      const data = await response.json();
      if (!data.ok) throw new Error(data.error || 'Unbekannter Fehler');
      return data.state;
    } catch (err) {
      showErrorBanner('Verbindung zum Server verloren – Reconnect läuft');
      console.error('Fetch error:', err);
      return null;
    }
  }

  async function sendControl(action, scenarioId) {
    try {
      const body = { action: action };
      if (scenarioId) body.scenarioId = scenarioId;
      
      const response = await fetch(API_BASE + '/api/control', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body)
      });
      
      if (!response.ok) throw new Error('HTTP ' + response.status);
      const data = await response.json();
      if (!data.ok) throw new Error(data.error || 'Unbekannter Fehler');
      return data.state;
    } catch (err) {
      showErrorBanner('Fehler bei Steuerung: ' + err.message);
      console.error('Control error:', err);
      return null;
    }
  }

  async function fetchArchitecture() {
    try {
      const response = await fetch(API_BASE + '/architecture.json');
      if (!response.ok) throw new Error('HTTP ' + response.status);
      const data = await response.json();
      if (!data.ok) throw new Error(data.error || 'Fehler');
      return data.graph;
    } catch (err) {
      console.error('Architecture fetch error:', err);
      return null;
    }
  }

  // UI-Updates
  function updateStatusBanner(state) {
    if (!state) return;
    
    const status = state.runStatus || 'ready';
    const banner = state.banner || 'Bereit';
    
    elements.statusBanner.textContent = banner;
    elements.statusBanner.className = 'status-banner status-' + status;
  }

  function updateButtons(state) {
    if (!state) return;
    
    const status = state.runStatus || 'ready';
    
    // Start: disabled wenn running
    elements.btnStart.disabled = (status === 'running');
    
    // Pause: disabled wenn nicht running
    elements.btnPause.disabled = (status !== 'running');
    
    // Einzelschritt: immer außer completed
    elements.btnStep.disabled = (status === 'completed');
    
    // Reset: immer
    elements.btnReset.disabled = false;
  }

  function updateContextPanel(state) {
    if (!state || !state.context) return;
    
    const ctx = state.context;
    elements.savedPct.textContent = Math.round(ctx.savedPct || 0) + '%';
    elements.rawTokens.textContent = formatNumber(ctx.rawTokens || 0);
    elements.keptTokens.textContent = formatNumber(ctx.keptTokens || 0);
    elements.summaries.textContent = ctx.summaries || 0;
  }

  function updateTelemetry(state) {
    if (!state || !state.telemetry) return;
    
    const tel = state.telemetry;
    elements.nodesVisited.textContent = tel.nodesVisited || 0;
    elements.checksRun.textContent = tel.checksRun || 0;
    elements.errorsCaught.textContent = tel.errorsCaught || 0;
    elements.recoveries.textContent = tel.recoveries || 0;
  }

  function formatNumber(num) {
    if (num >= 1000000) return (num / 1000000).toFixed(1) + 'M';
    if (num >= 1000) return (num / 1000).toFixed(1) + 'K';
    return String(num);
  }

  // Log-Funktionen
  function updateLog(state) {
    if (!state || !state.log) return;
    
    const logEntries = state.log.slice(-MAX_LOG_ENTRIES);
    const container = elements.logContainer;
    
    // Prüfe ob User unten ist
    const isAtBottom = container.scrollTop + container.clientHeight >= container.scrollHeight - 50;
    
    // Clear und neu rendern
    container.innerHTML = '';
    
    logEntries.forEach(function(entry) {
      const div = document.createElement('div');
      div.className = 'log-entry level-' + (entry.level || 'info');
      
      const msgSpan = document.createElement('span');
      msgSpan.className = 'log-msg';
      msgSpan.textContent = entry.msg || '';
      
      const timeSpan = document.createElement('span');
      timeSpan.className = 'log-time';
      timeSpan.textContent = formatTime(entry.t);
      
      div.appendChild(msgSpan);
      div.appendChild(timeSpan);
      
      if (entry.detail) {
        const detailDiv = document.createElement('div');
        detailDiv.className = 'log-detail';
        detailDiv.textContent = entry.detail;
        div.appendChild(detailDiv);
        
        div.addEventListener('click', function() {
          div.classList.toggle('expanded');
        });
      }
      
      container.appendChild(div);
    });
    
    // Autoscroll wenn unten
    if (logAutoScroll && isAtBottom) {
      container.scrollTop = container.scrollHeight;
    }
  }

  function addLogEntry(entry) {
    if (!state) state = { log: [] };
    if (!state.log) state.log = [];
    state.log.push(entry);
    updateLog(state);
  }

  function formatTime(timestamp) {
    if (!timestamp) return '';
    const date = new Date(timestamp);
    return date.toLocaleTimeString('de-DE', { hour: '2-digit', minute: '2-digit', second: '2-digit' });
  }

  // Graph-Rendering
  // Lange Knoten-Namen in max. 2 Zeilen umbrechen (gegen Label-Überlappung)
  function splitLabel(label) {
    if (label.indexOf('·') !== -1) {
      return label.split('·').map(function(s) { return s.trim(); }).filter(Boolean);
    }
    if (label.length > 12 && label.indexOf(' ') !== -1) {
      const words = label.split(' ');
      let best = 1, diff = Infinity;
      for (let i = 1; i < words.length; i++) {
        const a = words.slice(0, i).join(' ').length;
        const b = words.slice(i).join(' ').length;
        if (Math.abs(a - b) < diff) { diff = Math.abs(a - b); best = i; }
      }
      return [words.slice(0, best).join(' '), words.slice(best).join(' ')];
    }
    return [label];
  }

  function renderGraph(state) {
    if (!state) return;
    
    const nodes = state.nodes || [];
    const edges = state.edges || [];
    const worm = state.worm || {};
    const path = worm.path || [];
    const currentNodeId = worm.currentNodeId;
    
    // SVG leeren
    elements.graphSvg.innerHTML = '';
    
    // Defs für Pfeil
    const defs = document.createElementNS('http://www.w3.org/2000/svg', 'defs');
    const marker = document.createElementNS('http://www.w3.org/2000/svg', 'marker');
    marker.setAttribute('id', 'arrowhead');
    marker.setAttribute('markerWidth', '10');
    marker.setAttribute('markerHeight', '10');
    marker.setAttribute('refX', '9');
    marker.setAttribute('refY', '3');
    marker.setAttribute('orient', 'auto');
    const polygon = document.createElementNS('http://www.w3.org/2000/svg', 'polygon');
    polygon.setAttribute('points', '0 0, 10 3, 0 6');
    polygon.setAttribute('fill', '#475569');
    marker.appendChild(polygon);
    defs.appendChild(marker);
    elements.graphSvg.appendChild(defs);
    
    // Grid-Layout berechnen
    const padding = 60;
    const svgWidth = 800;
    const svgHeight = 600;
    
    // Max x/y finden
    let maxX = 0, maxY = 0;
    nodes.forEach(function(node) {
      if (node.x > maxX) maxX = node.x;
      if (node.y > maxY) maxY = node.y;
    });
    
    const cellWidth = maxX > 0 ? (svgWidth - 2 * padding) / maxX : 100;
    const cellHeight = maxY > 0 ? (svgHeight - 2 * padding) / maxY : 100;
    
    // Knoten-Positionen speichern
    const nodePositions = {};
    nodes.forEach(function(node) {
      nodePositions[node.id] = {
        x: padding + node.x * cellWidth,
        y: padding + node.y * cellHeight
      };
    });
    
    // Kanten zeichnen
    edges.forEach(function(edge) {
      const from = nodePositions[edge.from];
      const to = nodePositions[edge.to];
      if (!from || !to) return;
      
      const line = document.createElementNS('http://www.w3.org/2000/svg', 'line');
      line.setAttribute('x1', from.x);
      line.setAttribute('y1', from.y);
      line.setAttribute('x2', to.x);
      line.setAttribute('y2', to.y);
      line.setAttribute('class', 'graph-edge');
      
      // Prüfe ob Kante im Wurm-Pfad
      const fromIndex = path.indexOf(edge.from);
      const toIndex = path.indexOf(edge.to);
      if (fromIndex !== -1 && toIndex !== -1 && toIndex === fromIndex + 1) {
        line.setAttribute('class', 'graph-edge worm-path');
      }
      
      elements.graphSvg.appendChild(line);
    });
    
    // Knoten zeichnen
    nodes.forEach(function(node) {
      const pos = nodePositions[node.id];
      if (!pos) return;
      
      const g = document.createElementNS('http://www.w3.org/2000/svg', 'g');
      g.setAttribute('class', 'graph-node');
      g.setAttribute('transform', 'translate(' + pos.x + ',' + pos.y + ')');
      
      // Ring für aktuellen Knoten
      if (node.id === currentNodeId) {
        const ring = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
        ring.setAttribute('r', '38');
        ring.setAttribute('class', 'graph-node-ring');
        g.appendChild(ring);
        g.setAttribute('class', 'graph-node current');
      }
      
      // Hauptkreis
      const circle = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
      circle.setAttribute('r', '28');
      circle.setAttribute('class', 'graph-node-circle status-' + (node.status || 'pending'));
      
      if (node.status === 'active') {
        circle.setAttribute('class', 'graph-node-circle status-active active-pulse');
      }
      
      g.appendChild(circle);
      
      // Label unter dem Kreis, lange Namen zweizeilig (kein Überlappen)
      const text = document.createElementNS('http://www.w3.org/2000/svg', 'text');
      text.setAttribute('y', '46');
      text.setAttribute('class', 'graph-node-label');
      splitLabel(node.label || node.id).forEach(function(line, i) {
        const tspan = document.createElementNS('http://www.w3.org/2000/svg', 'tspan');
        tspan.setAttribute('x', '0');
        if (i > 0) tspan.setAttribute('dy', '14');
        tspan.textContent = line;
        text.appendChild(tspan);
      });
      g.appendChild(text);
      
      // Tooltip
      const title = document.createElementNS('http://www.w3.org/2000/svg', 'title');
      title.textContent = (node.label || node.id) + '\n' + (node.detail || '');
      g.appendChild(title);
      
      elements.graphSvg.appendChild(g);
    });
  }

  function renderArchitectureGraph(graph) {
    if (!graph) return;
    
    const nodes = graph.nodes || [];
    const edges = graph.edges || [];
    
    elements.graphSvg.innerHTML = '';
    
    // Defs für Pfeil
    const defs = document.createElementNS('http://www.w3.org/2000/svg', 'defs');
    const marker = document.createElementNS('http://www.w3.org/2000/svg', 'marker');
    marker.setAttribute('id', 'arrowhead');
    marker.setAttribute('markerWidth', '10');
    marker.setAttribute('markerHeight', '10');
    marker.setAttribute('refX', '9');
    marker.setAttribute('refY', '3');
    marker.setAttribute('orient', 'auto');
    const polygon = document.createElementNS('http://www.w3.org/2000/svg', 'polygon');
    polygon.setAttribute('points', '0 0, 10 3, 0 6');
    polygon.setAttribute('fill', '#475569');
    marker.appendChild(polygon);
    defs.appendChild(marker);
    elements.graphSvg.appendChild(defs);
    
    // Einfaches Layout: Gruppen nach BFS-Tiefe
    const svgWidth = 800;
    const svgHeight = 600;
    const padding = 80;
    
    // Gruppen sammeln
    const groups = {};
    nodes.forEach(function(node) {
      const group = node.group || 'core';
      if (!groups[group]) groups[group] = [];
      groups[group].push(node);
    });
    
    // Positionen berechnen
    const groupKeys = Object.keys(groups);
    const groupWidth = (svgWidth - 2 * padding) / Math.max(groupKeys.length, 1);
    
    const nodePositions = {};
    groupKeys.forEach(function(groupKey, groupIndex) {
      const groupNodes = groups[groupKey];
      const groupX = padding + groupIndex * groupWidth + groupWidth / 2;
      
      groupNodes.forEach(function(node, nodeIndex) {
        const y = padding + (nodeIndex + 1) * ((svgHeight - 2 * padding) / (groupNodes.length + 1));
        nodePositions[node.id] = { x: groupX, y: y };
      });
    });
    
    // Kanten
    edges.forEach(function(edge) {
      const from = nodePositions[edge.from];
      const to = nodePositions[edge.to];
      if (!from || !to) return;
      
      const line = document.createElementNS('http://www.w3.org/2000/svg', 'line');
      line.setAttribute('x1', from.x);
      line.setAttribute('y1', from.y);
      line.setAttribute('x2', to.x);
      line.setAttribute('y2', to.y);
      line.setAttribute('class', 'arch-edge');
      elements.graphSvg.appendChild(line);
    });
    
    // Knoten
    nodes.forEach(function(node) {
      const pos = nodePositions[node.id];
      if (!pos) return;
      
      const g = document.createElementNS('http://www.w3.org/2000/svg', 'g');
      g.setAttribute('transform', 'translate(' + pos.x + ',' + pos.y + ')');
      
      const circle = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
      circle.setAttribute('r', '24');
      circle.setAttribute('class', 'arch-node-circle group-' + (node.group || 'core'));
      g.appendChild(circle);
      
      const text = document.createElementNS('http://www.w3.org/2000/svg', 'text');
      text.setAttribute('y', '40');
      text.setAttribute('class', 'arch-node-label');
      text.textContent = node.label || node.id;
      g.appendChild(text);
      
      elements.graphSvg.appendChild(g);
    });
  }

  // Event-Handler
  function setupEventListeners() {
    // Buttons
    elements.btnStart.addEventListener('click', function() {
      sendControl('start').then(function(newState) {
        if (newState) updateUI(newState);
      });
    });

    elements.btnPause.addEventListener('click', function() {
      sendControl('pause').then(function(newState) {
        if (newState) updateUI(newState);
      });
    });

    elements.btnStep.addEventListener('click', function() {
      sendControl('step').then(function(newState) {
        if (newState) updateUI(newState);
      });
    });

    elements.btnReset.addEventListener('click', function() {
      sendControl('reset', selectedScenario).then(function(newState) {
        if (newState) updateUI(newState);
      });
    });

    // Szenario-Karten
    document.querySelectorAll('.scenario-card').forEach(function(card) {
      card.addEventListener('click', function() {
        document.querySelectorAll('.scenario-card').forEach(function(c) {
          c.classList.remove('selected');
        });
        card.classList.add('selected');
        selectedScenario = card.getAttribute('data-scenario');
        
        // Reset mit neuem Szenario
        sendControl('reset', selectedScenario).then(function(newState) {
          if (newState) updateUI(newState);
        });
      });
    });

    // Standard-Szenario auswählen
    document.querySelector('.scenario-card[data-scenario="happy-path"]').classList.add('selected');

    // Tab-Toggle
    elements.tabSimulation.addEventListener('click', function() {
      activeTab = 'simulation';
      elements.tabSimulation.classList.add('active');
      elements.tabArchitecture.classList.remove('active');
      if (state) renderGraph(state);
    });

    elements.tabArchitecture.addEventListener('click', async function() {
      activeTab = 'architecture';
      elements.tabArchitecture.classList.add('active');
      elements.tabSimulation.classList.remove('active');
      
      if (!architectureData) {
        architectureData = await fetchArchitecture();
      }
      if (architectureData) {
        renderArchitectureGraph(architectureData);
      }
    });

    // Log Autoscroll
    elements.logContainer.addEventListener('scroll', function() {
      const isAtBottom = elements.logContainer.scrollTop + elements.logContainer.clientHeight >= elements.logContainer.scrollHeight - 50;
      logAutoScroll = isAtBottom;
    });

    // Tastatur-Shortcuts
    document.addEventListener('keydown', function(e) {
      // Ignoriere wenn Input fokussiert
      if (e.target.tagName === 'INPUT' || e.target.tagName === 'TEXTAREA') return;
      
      switch(e.key) {
        case ' ':
          e.preventDefault();
          if (state && state.runStatus === 'running') {
            elements.btnPause.click();
          } else {
            elements.btnStart.click();
          }
          break;
        case 's':
        case 'S':
          e.preventDefault();
          elements.btnStep.click();
          break;
        case 'r':
        case 'R':
          e.preventDefault();
          elements.btnReset.click();
          break;
      }
    });
  }

  // UI-Update
  function updateUI(newState) {
    if (!newState) return;
    
    state = newState;
    
    updateStatusBanner(state);
    updateButtons(state);
    updateContextPanel(state);
    updateTelemetry(state);
    updateLog(state);
    
    if (activeTab === 'simulation') {
      renderGraph(state);
    }
    
    hideErrorBanner();
  }

  // Polling
  async function startPolling() {
    async function poll() {
      const newState = await fetchState();
      if (newState) {
        updateUI(newState);
      }
      pollTimer = setTimeout(poll, POLL_INTERVAL);
    }
    
    poll();
  }

  // Initialisierung
  // Szenario-Karten aus dem Backend synchronisieren (statische Karten als Fallback)
  function syncScenarioCards() {
    fetch('/api/scenarios').then(function(r) { return r.json(); }).then(function(data) {
      if (!data || !data.ok || !Array.isArray(data.scenarios)) return;
      data.scenarios.forEach(function(s) {
        const card = document.querySelector('.scenario-card[data-scenario="' + s.id + '"]');
        if (!card) return;
        const name = card.querySelector('.scenario-name');
        const desc = card.querySelector('.scenario-desc');
        if (name && s.name) name.textContent = s.name;
        if (desc && s.description) desc.textContent = s.description;
      });
    }).catch(function() { /* offline/fehler: statische Karten bleiben */ });
  }

  function init() {
    setupEventListeners();
    syncScenarioCards();
    startPolling();
  }

  // Start
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
