/**
 * dashboard.js — CryptoVeil v2 Real-Time Security & Forensic Operations Controller
 *
 * Full-featured interactive Desktop SOC Operations Center:
 *   • Dynamic WebSocket & REST communication (works across local desktop, loopback, or network)
 *   • Multi-Tab navigation (Live HUD, Process & MITRE, Forensic Lab, Simulator, Reports, Browser, Network, Portable Bundle)
 *   • Interactive D3.js Force-Directed Process Graph (Zoom, Pan, Drag, Node Inspector)
 *   • Real-Time Event Stream with Search, Severity Filters, and JSON Modal Inspector
 *   • Demonstration Lab: Live Forensic Tamper, Cryptographic Chain Verification & Off-Host Recovery
 *   • Interactive Threat & Anomaly Attack Simulator with real-time latency benchmark console
 *   • 24-Hour SOC Report Viewer with on-demand generation and PDF / CSV / JSON downloads
 *   • Web Audio API synthesizer for cyber sound effects (with mute toggle)
 *   • 1-Click Portable App Download and Local Network Discovery
 */

// ── Dynamic Network & API Configuration ────────────────────────────────────
const PROTOCOL    = location.protocol === 'https:' ? 'https:' : 'http:';
const WS_PROTOCOL = location.protocol === 'https:' ? 'wss:' : 'ws:';
const WS_URL      = `${WS_PROTOCOL}//${location.host}/ws/dashboard`;
const API_BASE    = `${PROTOCOL}//${location.host}/api`;

const MAX_EVENTS  = 300;
const RECONNECT_BASE = 1500;

// ── State ─────────────────────────────────────────────────────────────────
let ws                = null;
let reconnectDelay    = RECONNECT_BASE;
let totalEvents       = 0;
let threatCount       = 0;
let checkpoints       = 0;
let eventBuffer       = [];          // list of raw event objects
let processNodes      = {};          // pid → node data
let processLinks      = [];          // [{source, target}]
let simulation        = null;        // D3 force simulation
let hudSimulation     = null;        // HUD mini D3 simulation
let activeMitre       = new Set();   // mitre IDs seen this session
let browserEventCount = 0;
let extensionClients  = 0;
let soundEnabled      = true;
let currentFilterSev  = 'all';
let currentSearch     = '';
let selectedNodePid   = null;

// ── DOM References ────────────────────────────────────────────────────────
const $connPill       = document.getElementById('conn-pill');
const $connLabel      = document.getElementById('conn-label');
const $evTotal        = document.getElementById('ev-total');
const $evThreats      = document.getElementById('ev-threats');
const $evCheckpoints  = document.getElementById('ev-checkpoints');
const $evProcesses    = document.getElementById('ev-processes');
const $evBrowser      = document.getElementById('ev-browser');
const $evIntegrity    = document.getElementById('ev-integrity');
const $eventStream    = document.getElementById('event-stream');
const $streamCount    = document.getElementById('stream-count');
const $streamSearch   = document.getElementById('stream-search');
const $networkList    = document.getElementById('c2-list');
const $dgaList        = document.getElementById('dga-list');
const $browserEvents  = document.getElementById('browser-events');
const $shadowAiList   = document.getElementById('shadow-ai-list');
const $extStatusBadge = document.getElementById('ext-status-badge');
const $soundIcon      = document.getElementById('sound-icon');
const $headerLanText  = document.getElementById('header-lan-text');
const $eventModal     = document.getElementById('event-modal');
const $modalJson      = document.getElementById('modal-json');
const $modalTitle     = document.getElementById('modal-title');
const $simConsole     = document.getElementById('sim-console-output');

// ── Web Audio Synthesizer (Cyber Sound FX) ────────────────────────────────
const AudioCtx = window.AudioContext || window.webkitAudioContext;
let audioCtx = null;

function playCyberSound(type = 'beep') {
  if (!soundEnabled) return;
  try {
    if (!audioCtx) audioCtx = new AudioCtx();
    if (audioCtx.state === 'suspended') audioCtx.resume();

    const osc = audioCtx.createOscillator();
    const gain = audioCtx.createGain();
    osc.connect(gain);
    gain.connect(audioCtx.destination);

    const now = audioCtx.currentTime;
    if (type === 'threat') {
      osc.type = 'sawtooth';
      osc.frequency.setValueAtTime(440, now);
      osc.frequency.exponentialRampToValueAtTime(110, now + 0.35);
      gain.gain.setValueAtTime(0.18, now);
      gain.gain.exponentialRampToValueAtTime(0.01, now + 0.35);
      osc.start(now);
      osc.stop(now + 0.35);
    } else if (type === 'tamper') {
      osc.type = 'square';
      osc.frequency.setValueAtTime(880, now);
      osc.frequency.setValueAtTime(330, now + 0.15);
      gain.gain.setValueAtTime(0.2, now);
      gain.gain.exponentialRampToValueAtTime(0.01, now + 0.45);
      osc.start(now);
      osc.stop(now + 0.45);
    } else if (type === 'success') {
      osc.type = 'sine';
      osc.frequency.setValueAtTime(523.25, now);
      osc.frequency.exponentialRampToValueAtTime(659.25, now + 0.12);
      osc.frequency.exponentialRampToValueAtTime(783.99, now + 0.25);
      gain.gain.setValueAtTime(0.12, now);
      gain.gain.exponentialRampToValueAtTime(0.01, now + 0.3);
      osc.start(now);
      osc.stop(now + 0.3);
    } else {
      osc.type = 'sine';
      osc.frequency.setValueAtTime(880, now);
      gain.gain.setValueAtTime(0.05, now);
      gain.gain.exponentialRampToValueAtTime(0.001, now + 0.1);
      osc.start(now);
      osc.stop(now + 0.1);
    }
  } catch (_) {}
}

document.getElementById('btn-sound-toggle')?.addEventListener('click', () => {
  soundEnabled = !soundEnabled;
  if ($soundIcon) $soundIcon.textContent = soundEnabled ? '🔊' : '🔇';
  if (soundEnabled) playCyberSound('beep');
});

// ── Tab Navigation ────────────────────────────────────────────────────────
const navButtons = document.querySelectorAll('.nav-tab');
const tabContents = document.querySelectorAll('.tab-content');

navButtons.forEach(btn => {
  btn.addEventListener('click', () => {
    const targetId = btn.dataset.tab;
    navButtons.forEach(b => b.classList.remove('active'));
    tabContents.forEach(tc => tc.classList.remove('active'));

    btn.classList.add('active');
    const targetEl = document.getElementById(targetId);
    if (targetEl) targetEl.classList.add('active');

    // Trigger tab-specific refreshes
    if (targetId === 'tab-forensics') fetchEventsChain();
    if (targetId === 'tab-reports') loadReportsList();
    if (targetId === 'tab-browser') loadBrowserProfiles();
    if (targetId === 'tab-process' && simulation) simulation.alpha(0.3).restart();
  });
});

// Quick Action Buttons on Tab 1
document.getElementById('btn-quick-sim')?.addEventListener('click', () => {
  document.querySelector('[data-tab="tab-simulator"]')?.click();
  runSimulation('sim_all');
});

document.getElementById('btn-quick-verify')?.addEventListener('click', () => {
  document.querySelector('[data-tab="tab-forensics"]')?.click();
  verifyForensicChain();
});

document.getElementById('btn-quick-tamper')?.addEventListener('click', () => {
  document.querySelector('[data-tab="tab-forensics"]')?.click();
  simulateTamperAction();
});

document.getElementById('btn-quick-report')?.addEventListener('click', () => {
  document.querySelector('[data-tab="tab-reports"]')?.click();
  generateReportNow();
});

document.getElementById('btn-quick-attach-ext')?.addEventListener('click', () => {
  document.querySelector('[data-tab="tab-browser"]')?.click();
  loadBrowserProfiles();
});

// ── MITRE ATT&CK Technique Matrix Setup ───────────────────────────────────
const MITRE_TECHNIQUES = [
  { id: 'T1055.012', name: 'Process Hollowing', desc: 'Process injection by hollowing legitimate binaries (svchost.exe).' },
  { id: 'T1059.001', name: 'PowerShell Execution', desc: 'Execution of PowerShell scripts spawned from Office/external apps.' },
  { id: 'T1059.003', name: 'Command Shell', desc: 'Windows Command Prompt execution with obfuscated piping.' },
  { id: 'T1047',     name: 'WMI Abuse', desc: 'Windows Management Instrumentation used for execution/discovery.' },
  { id: 'T1218.005', name: 'Mshta LOLBin', desc: 'Living-off-the-Land execution via mshta.exe with remote URLs.' },
  { id: 'T1218.010', name: 'Regsvr32 Proxy', desc: 'Regsvr32 executing remote scriptlets (Squiblydoo attack).' },
  { id: 'T1036.005', name: 'Masquerading', desc: 'System binaries executing from anomalous, non-standard paths.' },
  { id: 'T1003.001', name: 'LSASS Memory Dump', desc: 'Credential dumping targeting Local Security Authority Subsystem Service.' },
  { id: 'T1070',     name: 'Indicator Removal', desc: 'Anti-forensic log deletion commands (wevtutil cl).' },
  { id: 'T1486',     name: 'Data Encrypted for Impact', desc: 'Ransomware burst high-entropy file encryption.' },
];

const mitreGrid = document.getElementById('mitre-grid');
if (mitreGrid) {
  MITRE_TECHNIQUES.forEach(t => {
    const b = document.createElement('div');
    b.className = 'mitre-badge';
    b.dataset.mitre = t.id;
    b.title = `${t.id}: ${t.name}\n${t.desc}`;
    b.innerHTML = `<strong>${t.id}</strong> <span>${t.name}</span>`;
    b.addEventListener('click', () => {
      openModal(`${t.id} — ${t.name}`, JSON.stringify(t, null, 2));
    });
    mitreGrid.appendChild(b);
  });
}

function activateMitre(mitreId) {
  activeMitre.add(mitreId);
  const badge = document.querySelector(`[data-mitre="${mitreId}"]`);
  if (badge) {
    badge.classList.add('active');
    flashEl(badge);
  }
}

// ── Interactive D3 Process Graph ──────────────────────────────────────────
function initProcessGraph() {
  const container = document.getElementById('process-graph-container');
  if (!container || typeof d3 === 'undefined') return;

  const w = container.clientWidth || 750;
  const h = container.clientHeight || 520;

  const svg = d3.select('#process-graph-container').append('svg')
    .attr('width', '100%')
    .attr('height', '100%')
    .attr('viewBox', `0 0 ${w} ${h}`);

  // Arrow markers
  svg.append('defs').append('marker')
    .attr('id', 'arrow-main')
    .attr('viewBox', '0 -5 10 10')
    .attr('refX', 22).attr('refY', 0)
    .attr('markerWidth', 6).attr('markerHeight', 6)
    .attr('orient', 'auto')
    .append('path')
      .attr('d', 'M0,-5L10,0L0,5')
      .attr('fill', 'rgba(0, 212, 255, 0.45)');

  const g = svg.append('g').attr('class', 'graph-root');

  // Zoom behaviour
  const zoom = d3.zoom()
    .scaleExtent([0.2, 4])
    .on('zoom', (event) => g.attr('transform', event.transform));

  svg.call(zoom);

  document.getElementById('btn-graph-zoom-in')?.addEventListener('click', () => {
    svg.transition().duration(300).call(zoom.scaleBy, 1.3);
  });
  document.getElementById('btn-graph-zoom-out')?.addEventListener('click', () => {
    svg.transition().duration(300).call(zoom.scaleBy, 0.7);
  });
  document.getElementById('btn-graph-reset')?.addEventListener('click', () => {
    svg.transition().duration(400).call(zoom.transform, d3.zoomIdentity);
  });

  const linkGroup = g.append('g').attr('class', 'links');
  const nodeGroup = g.append('g').attr('class', 'nodes');

  simulation = d3.forceSimulation()
    .force('link', d3.forceLink().id(d => d.pid).distance(80).strength(0.6))
    .force('charge', d3.forceManyBody().strength(-180))
    .force('center', d3.forceCenter(w / 2, h / 2))
    .force('collide', d3.forceCollide(30))
    .on('tick', () => {
      linkGroup.selectAll('line')
        .attr('x1', d => d.source.x).attr('y1', d => d.source.y)
        .attr('x2', d => d.target.x).attr('y2', d => d.target.y);
      nodeGroup.selectAll('.node')
        .attr('transform', d => `translate(${clamp(d.x, 25, w - 25)},${clamp(d.y, 25, h - 25)})`);
    });

  // Mini HUD graph
  const hudContainer = document.getElementById('hud-graph-container');
  if (hudContainer) {
    const hw = hudContainer.clientWidth || 550;
    const hh = hudContainer.clientHeight || 380;
    const hudSvg = d3.select('#hud-graph-container').append('svg')
      .attr('width', '100%').attr('height', '100%').attr('viewBox', `0 0 ${hw} ${hh}`);
    const hg = hudSvg.append('g');
    const hLinkG = hg.append('g');
    const hNodeG = hg.append('g');

    hudSimulation = d3.forceSimulation()
      .force('link', d3.forceLink().id(d => d.pid).distance(60).strength(0.5))
      .force('charge', d3.forceManyBody().strength(-120))
      .force('center', d3.forceCenter(hw / 2, hh / 2))
      .force('collide', d3.forceCollide(20))
      .on('tick', () => {
        hLinkG.selectAll('line')
          .attr('x1', d => d.source.x).attr('y1', d => d.source.y)
          .attr('x2', d => d.target.x).attr('y2', d => d.target.y);
        hNodeG.selectAll('.node')
          .attr('transform', d => `translate(${clamp(d.x, 20, hw - 20)},${clamp(d.y, 20, hh - 20)})`);
      });
  }
}

function clamp(v, lo, hi) { return Math.max(lo, Math.min(hi, v)); }

function nodeColor(d) {
  if (!d.suspicious) return '#0284c7';
  if (d.mitre_ids && d.mitre_ids.some(id => id.startsWith('T1055') || id.startsWith('T1003')))
    return '#ef4444';
  return '#f59e0b';
}

function updateGraph() {
  if (!simulation || typeof d3 === 'undefined') return;
  const nodes = Object.values(processNodes);
  const links = processLinks.filter(l => processNodes[l.source] && processNodes[l.target]);

  // Main Graph
  const svg = d3.select('#process-graph-container svg .graph-root');
  if (!svg.empty()) {
    const linkSel = svg.select('.links').selectAll('line').data(links, d => `${d.source}-${d.target}`);
    linkSel.enter().append('line')
      .attr('stroke', 'rgba(0, 212, 255, 0.3)')
      .attr('stroke-width', 1.5)
      .attr('marker-end', 'url(#arrow-main)')
      .merge(linkSel);
    linkSel.exit().remove();

    const nodeSel = svg.select('.nodes').selectAll('.node').data(nodes, d => d.pid);
    const enter = nodeSel.enter().append('g').attr('class', 'node')
      .call(d3.drag()
        .on('start', (ev, d) => { if (!ev.active) simulation.alphaTarget(0.3).restart(); d.fx = d.x; d.fy = d.y; })
        .on('drag', (ev, d) => { d.fx = ev.x; d.fy = ev.y; })
        .on('end', (ev, d) => { if (!ev.active) simulation.alphaTarget(0); d.fx = null; d.fy = null; })
      )
      .on('click', (ev, d) => inspectProcessNode(d));

    enter.append('circle')
      .attr('r', 15)
      .attr('fill', nodeColor)
      .attr('stroke', d => d.suspicious ? '#ef4444' : 'rgba(0, 212, 255, 0.6)')
      .attr('stroke-width', 2);

    enter.append('text')
      .attr('dy', 26)
      .attr('text-anchor', 'middle')
      .text(d => d.name.length > 14 ? d.name.slice(0, 13) + '…' : d.name);

    svg.selectAll('.node circle')
      .attr('fill', nodeColor)
      .attr('stroke', d => d.suspicious ? '#ef4444' : 'rgba(0, 212, 255, 0.6)');

    nodeSel.exit().remove();

    simulation.nodes(nodes);
    simulation.force('link').links(links.map(l => ({
      source: processNodes[l.source] || l.source,
      target: processNodes[l.target] || l.target,
    })));
    simulation.alpha(0.3).restart();
  }

  // Mini HUD Graph
  const hudSvg = d3.select('#hud-graph-container svg g');
  if (!hudSvg.empty() && hudSimulation) {
    const hLinkSel = hudSvg.select('g:first-child').selectAll('line').data(links, d => `${d.source}-${d.target}`);
    hLinkSel.enter().append('line')
      .attr('stroke', 'rgba(0, 212, 255, 0.25)')
      .attr('stroke-width', 1)
      .merge(hLinkSel);
    hLinkSel.exit().remove();

    const hNodeSel = hudSvg.select('g:last-child').selectAll('.node').data(nodes, d => d.pid);
    const hEnter = hNodeSel.enter().append('g').attr('class', 'node');
    hEnter.append('circle')
      .attr('r', 10)
      .attr('fill', nodeColor)
      .attr('stroke', 'rgba(0, 212, 255, 0.4)')
      .attr('stroke-width', 1.5);
    hEnter.append('text')
      .attr('dy', 18)
      .attr('text-anchor', 'middle')
      .style('font-size', '8px')
      .text(d => d.name.length > 10 ? d.name.slice(0, 9) + '…' : d.name);

    hudSvg.selectAll('.node circle').attr('fill', nodeColor);
    hNodeSel.exit().remove();

    hudSimulation.nodes(nodes);
    hudSimulation.force('link').links(links.map(l => ({
      source: processNodes[l.source] || l.source,
      target: processNodes[l.target] || l.target,
    })));
    hudSimulation.alpha(0.2).restart();
  }

  if ($evProcesses) $evProcesses.textContent = nodes.length;
}

function inspectProcessNode(d) {
  selectedNodePid = d.pid;
  const inspector = document.getElementById('inspector-content');
  const badge = document.getElementById('inspector-badge');
  if (!inspector) return;

  if (badge) {
    badge.textContent = `PID: ${d.pid}`;
    badge.style.color = d.suspicious ? 'var(--red)' : 'var(--cyan)';
  }

  inspector.innerHTML = `
    <div class="inspector-row"><span class="label">Process Name:</span> <span class="val">${escapeHtml(d.name)}</span></div>
    <div class="inspector-row"><span class="label">Process ID (PID):</span> <span class="val">${d.pid}</span></div>
    <div class="inspector-row"><span class="label">Parent PID (PPID):</span> <span class="val">${d.ppid || 'None'}</span></div>
    <div class="inspector-row"><span class="label">Executable Path:</span> <span class="val" style="font-size:0.68rem;">${escapeHtml(d.exe || 'N/A')}</span></div>
    <div class="inspector-row"><span class="label">Threat Status:</span> <span class="val" style="color:${d.suspicious ? 'var(--red)' : 'var(--green)'};">${d.suspicious ? 'SUSPICIOUS / MITRE ALERT' : 'NORMAL ACTIVITY'}</span></div>
    ${d.mitre_ids && d.mitre_ids.length ? `<div class="inspector-row"><span class="label">Triggered MITRE:</span> <span class="val" style="color:var(--red);">${d.mitre_ids.join(', ')}</span></div>` : ''}
    <div style="margin-top:0.75rem;">
      <button class="btn-action primary" style="width:100%;justify-content:center;" onclick="openModal('Process Record (PID ${d.pid})', JSON.stringify(processNodes[${d.pid}], null, 2))">
        Inspect Full Telemetry Record
      </button>
    </div>
  `;
}

// ── Event Stream Rendering & Filter Management ────────────────────────────
function renderEvent(entry) {
  const ev = entry.entry || entry;
  const sev = ev.severity || 'info';
  const ts = new Date((ev.timestamp || Date.now() / 1000) * 1000).toLocaleTimeString();
  const topic = ev.topic || ev.event_type || '—';

  // Store in buffer
  eventBuffer.unshift(ev);
  if (eventBuffer.length > MAX_EVENTS) eventBuffer.pop();

  if ($streamCount) $streamCount.textContent = `${eventBuffer.length} items`;

  // Filter check
  if (!matchesFilter(ev)) return;

  if ($eventStream) {
    const empty = $eventStream.querySelector('.empty-state');
    if (empty) empty.remove();

    const userEmail = ev.user_email || ev.data?.user_email || ev.detail?.user_email || '';
    const browserName = ev.browser_name || ev.data?.browser_name || ev.detail?.browser_name || '';

    const item = document.createElement('div');
    item.className = 'event-item';
    item.dataset.sev = sev;
    item.dataset.topic = topic;

    item.innerHTML = `
      <div class="sev-dot ${sev}"></div>
      <div style="flex:1;min-width:0;">
        <div style="display:flex;justify-content:space-between;align-items:center;gap:0.5rem;">
          <div style="display:flex;align-items:center;gap:6px;">
            <span class="event-topic">${escapeHtml(topic)}</span>
            ${userEmail ? `<span class="event-email-badge" title="Browser: ${escapeHtml(browserName)}">👤 ${escapeHtml(userEmail)}</span>` : ''}
          </div>
          <div class="event-ts">${ts}</div>
        </div>
        <div class="event-detail">${formatEventDetail(ev)}</div>
      </div>
    `;

    item.addEventListener('click', () => {
      openModal(`${topic} (Severity: ${sev.toUpperCase()})`, JSON.stringify(ev, null, 2));
    });

    $eventStream.prepend(item);

    // Cap DOM children
    while ($eventStream.children.length > MAX_EVENTS) {
      $eventStream.lastChild.remove();
    }
  }
}

function formatEventDetail(ev) {
  const data = ev.data || ev.detail || {};
  const pairs = [];
  for (const [k, v] of Object.entries(data)) {
    if (k === 'user_email' || k === 'browser_name') continue;
    if (pairs.length >= 3) break;
    pairs.push(`${k}=${typeof v === 'object' ? JSON.stringify(v) : v}`);
  }
  return pairs.join('  ') || ev.source || ev.description || 'Security telemetry event captured';
}

function matchesFilter(ev) {
  const sev = ev.severity || 'info';
  if (currentFilterSev !== 'all' && sev !== currentFilterSev) return false;

  if (currentSearch) {
    const q = currentSearch.toLowerCase();
    const str = JSON.stringify(ev).toLowerCase();
    if (!str.includes(q)) return false;
  }
  return true;
}

function reapplyFilters() {
  if (!$eventStream) return;
  $eventStream.innerHTML = '';
  const filtered = eventBuffer.filter(matchesFilter);
  if (filtered.length === 0) {
    $eventStream.innerHTML = `<div class="empty-state">No events matching current filter</div>`;
    return;
  }
  filtered.forEach(ev => {
    const sev = ev.severity || 'info';
    const ts = new Date((ev.timestamp || Date.now() / 1000) * 1000).toLocaleTimeString();
    const topic = ev.topic || ev.event_type || '—';
    const userEmail = ev.user_email || ev.data?.user_email || ev.detail?.user_email || '';
    const browserName = ev.browser_name || ev.data?.browser_name || ev.detail?.browser_name || '';

    const item = document.createElement('div');
    item.className = 'event-item';
    item.innerHTML = `
      <div class="sev-dot ${sev}"></div>
      <div style="flex:1;min-width:0;">
        <div style="display:flex;justify-content:space-between;align-items:center;gap:0.5rem;">
          <div style="display:flex;align-items:center;gap:6px;">
            <span class="event-topic">${escapeHtml(topic)}</span>
            ${userEmail ? `<span class="event-email-badge" title="Browser: ${escapeHtml(browserName)}">👤 ${escapeHtml(userEmail)}</span>` : ''}
          </div>
          <div class="event-ts">${ts}</div>
        </div>
        <div class="event-detail">${formatEventDetail(ev)}</div>
      </div>
    `;
    item.addEventListener('click', () => {
      openModal(`${topic} (Severity: ${sev.toUpperCase()})`, JSON.stringify(ev, null, 2));
    });
    $eventStream.appendChild(item);
  });
}

document.querySelectorAll('.btn-sev').forEach(btn => {
  btn.addEventListener('click', () => {
    document.querySelectorAll('.btn-sev').forEach(b => b.classList.remove('active'));
    btn.classList.add('active');
    currentFilterSev = btn.dataset.sev;
    reapplyFilters();
  });
});

$streamSearch?.addEventListener('input', (e) => {
  currentSearch = e.target.value.trim();
  reapplyFilters();
});

document.getElementById('btn-clear-stream')?.addEventListener('click', () => {
  if ($eventStream) $eventStream.innerHTML = `<div class="empty-state">Event stream cleared</div>`;
});

// ── Event Dispatcher (WebSocket Receiver) ─────────────────────────────────
function dispatch(msg) {
  const entry = msg.entry || msg;
  const topic = entry.topic || entry.event_type || '';
  const data  = (entry.data && typeof entry.data === 'object' && Object.keys(entry.data).length > 0) ? { ...entry, ...entry.data } : entry;
  const sev   = entry.severity || 'info';

  totalEvents++;
  if ($evTotal) bumpStat($evTotal, totalEvents);
  renderEvent(msg);

  // Audio alert on threats
  if (sev === 'critical' || sev === 'high') {
    playCyberSound('threat');
  }

  // Process Spawned
  if (topic === 'sensor.process.spawned') {
    processNodes[data.pid] = {
      pid: data.pid,
      name: data.name || 'unknown',
      exe: data.exe || '',
      ppid: data.ppid || 0,
      suspicious: false,
      mitre_ids: [],
    };
    if (data.ppid && processNodes[data.ppid]) {
      processLinks.push({ source: data.ppid, target: data.pid });
    }
    updateGraph();
  }

  // Process Terminated
  if (topic === 'sensor.process.terminated') {
    delete processNodes[data.pid];
    processLinks = processLinks.filter(l => l.source !== data.pid && l.target !== data.pid);
    updateGraph();
  }

  // Filesystem Entropy (Burst / Ransomware)
  if (topic === 'sensor.filesystem.entropy' && data.burst_triggered) {
    threatCount++;
    if ($evThreats) bumpStat($evThreats, threatCount);
    activateMitre('T1486');
  }

  // Clipboard Swap / Hijack
  if (topic === 'sensor.clipboard.swap') {
    threatCount++;
    if ($evThreats) bumpStat($evThreats, threatCount);
  }

  // Anti-Forensics
  if (topic === 'engine.antiforensic.detected') {
    threatCount++;
    if ($evThreats) bumpStat($evThreats, threatCount);
    activateMitre('T1070');
  }

  // MITRE Alert
  if (topic === 'engine.mitre.alert') {
    threatCount++;
    if ($evThreats) bumpStat($evThreats, threatCount);
    if (data.pid && processNodes[data.pid]) {
      processNodes[data.pid].suspicious = true;
      processNodes[data.pid].mitre_ids = processNodes[data.pid].mitre_ids || [];
      processNodes[data.pid].mitre_ids.push(data.mitre_id);
      updateGraph();
    }
    activateMitre(data.mitre_id);
  }

  // C2 Beacon
  if (topic === 'engine.network.c2') {
    threatCount++;
    if ($evThreats) bumpStat($evThreats, threatCount);
    addNetworkRow('c2', `${data.remote_addr}:${data.remote_port} (${data.process_name || 'proc'}, CoV=${data.coefficient_of_variation || 0.05})`);
  }

  // DGA
  if (topic === 'engine.network.dga') {
    threatCount++;
    if ($evThreats) bumpStat($evThreats, threatCount);
    addDgaRow(`${data.hostname} (entropy=${data.entropy_score || 4.1}, vowels=${data.vowel_ratio || 0.12})`);
  }

  // Checkpoint sealed
  if (topic === 'forensics.checkpoint' || topic === 'forensics.checkpoint.sealed') {
    checkpoints++;
    if ($evCheckpoints) bumpStat($evCheckpoints, checkpoints);
    playCyberSound('success');
    fetchEventsChain();
  }

  // Browser telemetry
  if (topic === 'browser.telemetry') {
    addBrowserEvent(data || entry);
    if (entry.trust_score !== undefined && entry.trust_score < 50) {
      threatCount++;
      if ($evThreats) bumpStat($evThreats, threatCount);
    }
  }
}

function addNetworkRow(type, label) {
  if (!$networkList) return;
  const empty = $networkList.querySelector('.empty-state');
  if (empty) empty.remove();

  const row = document.createElement('div');
  row.className = 'net-row';
  row.innerHTML = `
    <span class="net-type ${type}">${type.toUpperCase()}</span>
    <span style="flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">${escapeHtml(label)}</span>
    <span style="font-size:0.6rem;color:var(--text-dim);">${new Date().toLocaleTimeString()}</span>
  `;
  $networkList.prepend(row);
  while ($networkList.children.length > 30) $networkList.lastChild.remove();
}

function addDgaRow(label) {
  if (!$dgaList) return;
  const empty = $dgaList.querySelector('.empty-state');
  if (empty) empty.remove();

  const row = document.createElement('div');
  row.className = 'net-row';
  row.innerHTML = `
    <span class="net-type dga">DGA</span>
    <span style="flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">${escapeHtml(label)}</span>
    <span style="font-size:0.6rem;color:var(--text-dim);">${new Date().toLocaleTimeString()}</span>
  `;
  $dgaList.prepend(row);
  while ($dgaList.children.length > 30) $dgaList.lastChild.remove();
}

function addBrowserEvent(data) {
  if (!$browserEvents) return;
  const empty = $browserEvents.querySelector('.empty-state');
  if (empty) empty.remove();

  const kind = data.event_kind || data.type || 'site_visit';
  const hostname = data.hostname || data.aiDomain || 'unknown';
  const score = data.trust_score ?? data.score;
  const userEmail = data.user_email || data.detail?.user_email || '';
  const browserName = data.browser_name || data.detail?.browser_name || '';
  const ts = new Date().toLocaleTimeString();

  const row = document.createElement('div');
  row.className = 'browser-event-row';
  row.innerHTML = `
    <span class="browser-event-kind ${kindClass(kind)}">${kindLabel(kind)}</span>
    <span class="browser-event-host">${escapeHtml(hostname)}</span>
    ${userEmail ? `<span class="browser-email-pill" title="${escapeHtml(browserName)}">👤 ${escapeHtml(userEmail)}</span>` : ''}
    ${score !== undefined && score !== null ? `<span class="browser-event-score ${scoreClass(score)}">${score}</span>` : ''}
    <span style="font-size:0.6rem;color:var(--text-dim);">${ts}</span>
  `;
  $browserEvents.prepend(row);
  while ($browserEvents.children.length > 40) $browserEvents.lastChild.remove();

  // Shadow AI specific list
  if (kind.includes('shadow_ai') && $shadowAiList) {
    const sEmpty = $shadowAiList.querySelector('.empty-state');
    if (sEmpty) sEmpty.remove();
    const sRow = document.createElement('div');
    sRow.className = 'browser-event-row';
    sRow.innerHTML = `
      <span class="browser-event-kind ai">AI API</span>
      <span class="browser-event-host">${escapeHtml(hostname)}</span>
      ${userEmail ? `<span class="browser-email-pill" style="font-size:0.65rem;">👤 ${escapeHtml(userEmail)}</span>` : ''}
      <span style="font-size:0.6rem;color:var(--text-dim);">${ts}</span>
    `;
    $shadowAiList.prepend(sRow);
  }

  browserEventCount++;
  if ($evBrowser) {
    $evBrowser.textContent = `${browserEventCount} events`;
    flashEl($evBrowser);
  }
}

function kindClass(k) {
  if (k.includes('shadow_ai')) return 'ai';
  if (k.includes('warn') || k.includes('threat')) return 'warn';
  return 'visit';
}

function kindLabel(k) {
  if (k.includes('shadow_ai')) return 'SHADOW AI';
  if (k.includes('site_warning')) return 'PHISHING';
  if (k.includes('obfuscation')) return 'OBFUSC';
  return 'VISIT';
}

function scoreClass(s) {
  if (s >= 75) return 'safe';
  if (s >= 50) return 'caution';
  return 'danger';
}

// ── WebSocket Connection Manager ──────────────────────────────────────────
function connectWebSocket() {
  ws = new WebSocket(WS_URL);

  ws.onopen = () => {
    reconnectDelay = RECONNECT_BASE;
    if ($connPill) $connPill.classList.add('connected');
    if ($connLabel) $connLabel.textContent = 'ONLINE';
    logToConsole('[AGENT] Connected to CryptoVeil Security Event Engine.', 'success');
  };

  ws.onmessage = (e) => {
    try {
      const msg = JSON.parse(e.data);
      if (msg.kind === 'event' || msg.topic || msg.event_id || msg.entry || msg.severity) {
        dispatch(msg);
      }
    } catch (_) {}
  };

  ws.onclose = () => {
    if ($connPill) $connPill.classList.remove('connected');
    if ($connLabel) $connLabel.textContent = 'RECONNECTING…';
    setTimeout(connectWebSocket, reconnectDelay);
    reconnectDelay = Math.min(reconnectDelay * 1.5, 20000);
  };

  ws.onerror = () => ws.close();
}

// ── Forensic Tamper Demonstration & Verification Lab ──────────────────────
async function verifyForensicChain() {
  const box = document.getElementById('verification-box');
  const icon = document.getElementById('verif-icon');
  const title = document.getElementById('verif-title');
  const details = document.getElementById('verif-details');
  const badge = document.getElementById('chain-status-badge');

  if (box) box.style.display = 'block';
  if (details) details.innerHTML = '<span style="color:var(--cyan);">Calculating sequential SHA-256 hash chains across all stored events…</span>';

  try {
    const res = await fetch(`${API_BASE}/forensics/verify_chain`);
    const data = await res.json();

    if (data.verified) {
      if (box) box.className = 'verification-box valid';
      if (icon) icon.textContent = '✓';
      if (title) title.textContent = `ALL ${data.total_events} EVENTS CRYPTOGRAPHICALLY VERIFIED`;
      if (badge) {
        badge.textContent = 'Integrity: Intact ✓';
        badge.style.color = 'var(--green)';
      }
      if ($evIntegrity) {
        $evIntegrity.textContent = 'VERIFIED ✓';
        $evIntegrity.style.color = 'var(--green)';
      }
      if (details) {
        details.innerHTML = `
          <div><strong>Status:</strong> PASS (100% Cryptographically Intact)</div>
          <div><strong>Total Evaluated Entries:</strong> ${data.total_events} events verified sequentially.</div>
          <div><strong>Tamper Violations:</strong> 0 detected.</div>
        `;
      }
      playCyberSound('success');
      logToConsole(`[FORENSICS] Hash chain verified: ${data.total_events} entries intact.`, 'success');
    } else {
      if (box) box.className = 'verification-box invalid';
      if (icon) icon.textContent = '✕';
      if (title) title.textContent = `TAMPERING DETECTED (${data.violations.length} VIOLATION${data.violations.length > 1 ? 'S' : ''})`;
      if (badge) {
        badge.textContent = 'COMPROMISED ✕';
        badge.style.color = 'var(--red)';
      }
      if ($evIntegrity) {
        $evIntegrity.textContent = 'COMPROMISED ✕';
        $evIntegrity.style.color = 'var(--red)';
      }

      const vRows = data.violations.map(v => `
        <div style="margin-top:0.4rem;padding:0.4rem;background:rgba(239,68,68,0.15);border-radius:4px;">
          <div>🚨 <strong>Sequence #${v.seq} Altered!</strong> (Event ID: ${v.event_id || 'N/A'})</div>
          <div style="font-size:0.7rem;color:#fca5a5;">Expected Hash: <code>${v.expected_hash}</code></div>
          <div style="font-size:0.7rem;color:#fca5a5;">Actual Hash:   <code>${v.actual_hash}</code></div>
        </div>
      `).join('');

      if (details) {
        details.innerHTML = `
          <div><strong style="color:var(--red);">CRITICAL INTEGRITY FAILURE:</strong> Local log records were altered after cryptographic sealing!</div>
          ${vRows}
        `;
      }
      playCyberSound('tamper');
      logToConsole(`[FORENSICS ALERT] Chain verification failed: ${data.violations.length} violations detected!`, 'danger');
    }
  } catch (err) {
    if (box) box.className = 'verification-box invalid';
    if (title) title.textContent = 'Verification Request Error';
    if (details) details.textContent = err.message;
  }
}

async function simulateTamperAction() {
  try {
    const res = await fetch(`${API_BASE}/forensics/verify_chain`);
    const data = await res.json();
    const targetSeq = Math.max(0, Math.floor(data.total_events / 2));

    const simRes = await fetch(`${API_BASE}/forensics/simulate_tamper/${targetSeq}`, { method: 'POST' });
    if (!simRes.ok) throw new Error(await simRes.text());

    logToConsole(`[TAMPER SIM] Mutated local record seq #${targetSeq} to demonstrate tamper detection.`, 'warn');
    playCyberSound('tamper');
    await verifyForensicChain();
    fetchEventsChain();
  } catch (err) {
    logToConsole(`[TAMPER SIM ERROR] ${err.message}`, 'danger');
  }
}

async function fetchOffhostCleanCopy() {
  try {
    const res = await fetch(`${API_BASE}/forensics/verify_chain`);
    const data = await res.json();
    const targetSeq = Math.max(0, Math.floor(data.total_events / 2));

    const offRes = await fetch(`${API_BASE}/forensics/offhost/${targetSeq}`);
    if (offRes.status === 200) {
      const record = await offRes.json();
      openModal(`Off-Host Evidence Copy (Seq #${targetSeq})`, JSON.stringify(record, null, 2));
      logToConsole(`[OFF-HOST] Retrieved clean replicated record seq #${targetSeq} from off-host storage.`, 'success');
    } else {
      logToConsole(`[OFF-HOST] No batch checkpoint covering seq #${targetSeq} has been sealed yet. Run simulations to seal a checkpoint.`, 'warn');
    }
  } catch (err) {
    logToConsole(`[OFF-HOST ERROR] ${err.message}`, 'danger');
  }
}

async function fetchEventsChain() {
  const chainList = document.getElementById('chain-list');
  if (!chainList) return;

  try {
    const res = await fetch(`${API_BASE}/forensics/events_chain?limit=50`);
    const { chain } = await res.json();

    if (!chain || chain.length === 0) {
      chainList.innerHTML = `<div class="empty-state">No events recorded in cryptographic hash chain yet.</div>`;
      return;
    }

    chainList.innerHTML = '';
    chain.slice().reverse().forEach(block => {
      const el = document.createElement('div');
      el.className = 'chain-block';
      el.innerHTML = `
        <div class="chain-seq">#${block.seq}</div>
        <div class="chain-hashes">
          <div class="chain-hash-row">
            <span class="chain-hash-label">HASH:</span>
            <span class="chain-hash-val">${block.hash.slice(0, 24)}…</span>
          </div>
          <div class="chain-hash-row">
            <span class="chain-hash-label">PREV:</span>
            <span class="chain-hash-val">${block.prev_hash.slice(0, 24)}…</span>
          </div>
        </div>
        <div style="font-size:0.65rem;color:var(--cyan);min-width:90px;text-align:right;">${escapeHtml(block.topic)}</div>
        <div class="chain-status ok">SEALED</div>
      `;
      el.addEventListener('click', () => {
        openModal(`Chain Entry #${block.seq}`, JSON.stringify(block, null, 2));
      });
      chainList.appendChild(el);
    });
  } catch (_) {}
}

// Merkle Inclusion Proof Verifier
document.getElementById('btn-fetch-proof')?.addEventListener('click', async () => {
  const seqInput = document.getElementById('proof-seq');
  const seq = seqInput ? seqInput.value.trim() : '';
  const resBox = document.getElementById('proof-result');
  if (!seq || !resBox) return;

  resBox.style.display = 'block';
  resBox.className = 'proof-result';
  resBox.textContent = 'Fetching inclusion proof…';

  try {
    const r = await fetch(`${API_BASE}/forensics/proof/${seq}`);
    if (!r.ok) throw new Error(await r.text());
    const proof = await r.json();

    const vr = await fetch(`${API_BASE}/forensics/verify_proof`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(proof),
    });
    const result = await vr.json();

    if (result.valid) {
      resBox.className = 'proof-result valid';
      resBox.innerHTML = `
        <div><strong>✓ RFC 6962 Inclusion Proof VALID</strong></div>
        <div>Event #${seq} is cryptographically bound to Checkpoint #${proof.checkpoint_seq}.</div>
        <div>Merkle Root: <code>${proof.merkle_root.slice(0, 24)}…</code></div>
        <div>Digital Signature (Ed25519): <strong>VERIFIED ✓</strong></div>
        <div>Audit Tree Path Depth: <strong>${proof.audit_path.length} sibling hashes</strong></div>
      `;
      playCyberSound('success');
    } else {
      resBox.className = 'proof-result invalid';
      resBox.textContent = `✗ Proof Verification FAILED for event #${seq}.`;
      playCyberSound('tamper');
    }
  } catch (err) {
    resBox.className = 'proof-result invalid';
    resBox.textContent = `Proof Error: ${err.message}`;
  }
});

document.getElementById('btn-verify-chain')?.addEventListener('click', verifyForensicChain);
document.getElementById('btn-simulate-tamper')?.addEventListener('click', simulateTamperAction);
document.getElementById('btn-fetch-offhost')?.addEventListener('click', fetchOffhostCleanCopy);
document.getElementById('btn-refresh-chain')?.addEventListener('click', fetchEventsChain);

// ── Interactive Attack Simulator Lab ──────────────────────────────────────
async function runSimulation(simName) {
  logToConsole(`[SIMULATOR] Launching simulation: ${simName}…`, 'info');
  try {
    const t0 = performance.now();
    const res = await fetch(`${API_BASE}/simulations/run/${simName}`, { method: 'POST' });
    const data = await res.json();
    const elapsed = Math.round(performance.now() - t0);

    if (data.status === 'TRIGGERED' || data.status === 'SUCCESS' || data.status === 'ALL_TRIGGERED') {
      logToConsole(`[SUCCESS] ${data.simulation} — Latency: ${data.detection_latency_ms || elapsed}ms: ${data.detail}`, 'success');
      playCyberSound('beep');
    } else {
      logToConsole(`[NOTICE] ${data.simulation}: ${data.detail}`, 'warn');
    }
  } catch (err) {
    logToConsole(`[ERROR] Failed to run ${simName}: ${err.message}`, 'danger');
  }
}

document.querySelectorAll('.sim-btn').forEach(btn => {
  btn.addEventListener('click', () => {
    runSimulation(btn.dataset.sim);
  });
});

document.getElementById('btn-run-all-sims')?.addEventListener('click', () => {
  runSimulation('sim_all');
});

document.getElementById('btn-clear-console')?.addEventListener('click', () => {
  if ($simConsole) $simConsole.innerHTML = `<div class="console-line info">[CONSOLE] Ready for simulation trigger.</div>`;
});

function logToConsole(msg, level = 'info') {
  if (!$simConsole) return;
  const line = document.createElement('div');
  line.className = `console-line ${level}`;
  line.innerHTML = `[${new Date().toLocaleTimeString()}] ${escapeHtml(msg)}`;
  $simConsole.appendChild(line);
  $simConsole.scrollTop = $simConsole.scrollHeight;
}

// ── 24-Hour Automated SOC Reports ─────────────────────────────────────────
async function loadReportsList() {
  const sel = document.getElementById('report-date-select');
  if (!sel) return;

  try {
    const res = await fetch(`${API_BASE}/reports`);
    const { reports } = await res.json();

    sel.innerHTML = '';
    if (!reports || reports.length === 0) {
      sel.innerHTML = '<option value="">No reports available</option>';
      return;
    }

    reports.forEach(r => {
      const opt = document.createElement('option');
      opt.value = r.date;
      opt.textContent = `${r.date} (${r.status || 'NORMAL'}, ${r.total_events} events)`;
      sel.appendChild(opt);
    });

    if (sel.value) renderReport(sel.value);
  } catch (_) {}
}

async function renderReport(dateStr) {
  if (!dateStr) return;
  try {
    const res = await fetch(`${API_BASE}/reports/${dateStr}`);
    if (!res.ok) return;
    const rep = await res.json();

    const titleEl = document.getElementById('rep-date-title');
    if (titleEl) titleEl.textContent = `Daily SOC Report — ${rep.date}`;
    const genEl = document.getElementById('rep-generated-at');
    if (genEl) genEl.textContent = `Generated: ${new Date(rep.generated_at).toLocaleString()}`;

    const ex = rep.executive_summary || {};
    const stEl = document.getElementById('rep-status');
    if (stEl) {
      stEl.textContent = ex.overall_status || 'NORMAL';
      stEl.style.color = ex.overall_status === 'NORMAL' ? 'var(--green)' : 'var(--red)';
    }

    const tEv = document.getElementById('rep-total-events');
    if (tEv) tEv.textContent = ex.total_events || 0;
    const thDet = document.getElementById('rep-threats-detected');
    if (thDet) thDet.textContent = ex.threats_detected || 0;
    const thBlk = document.getElementById('rep-threats-blocked');
    if (thBlk) thBlk.textContent = ex.threats_blocked || 0;

    const b = rep.browser_security || {};
    const bSites = document.getElementById('rep-b-sites');
    if (bSites) bSites.textContent = b.sites_analyzed || 0;
    const bSusp = document.getElementById('rep-b-suspicious');
    if (bSusp) bSusp.textContent = b.suspicious_sites || 0;
    const bBlk = document.getElementById('rep-b-blocked');
    if (bBlk) bBlk.textContent = b.blocked_pages || 0;
    const bSh = document.getElementById('rep-b-shadowai');
    if (bSh) bSh.textContent = b.shadow_ai_detections || 0;
    const bMask = document.getElementById('rep-b-masks');
    if (bMask) bMask.textContent = b.sensitive_field_protection_events || 0;

    const ep = rep.endpoint_security || {};
    const epProc = document.getElementById('rep-e-proc');
    if (epProc) epProc.textContent = ep.suspicious_processes || 0;
    const epClip = document.getElementById('rep-e-clip');
    if (epClip) epClip.textContent = ep.clipboard_hijack_attempts || 0;
    const epBurst = document.getElementById('rep-e-burst');
    if (epBurst) epBurst.textContent = ep.file_ransomware_anomalies || 0;
    const epAnti = document.getElementById('rep-e-antiforensic');
    if (epAnti) epAnti.textContent = ep.anti_forensic_activity || 0;
    const epNet = document.getElementById('rep-e-net');
    if (epNet) epNet.textContent = ep.network_anomalies || 0;

    const f = rep.forensic_integrity || {};
    const fTot = document.getElementById('rep-f-total');
    if (fTot) fTot.textContent = f.total_evidence_events || 0;
    const fChain = document.getElementById('rep-f-chain');
    if (fChain) {
      fChain.textContent = f.hash_chain_verified ? 'PASS ✓' : 'FAILED ✕';
      fChain.style.color = f.hash_chain_verified ? 'var(--green)' : 'var(--red)';
    }
    const fCheck = document.getElementById('rep-f-checkpoints');
    if (fCheck) fCheck.textContent = f.merkle_checkpoints_sealed || 0;

    // MITRE Table
    const mitreContainer = document.getElementById('rep-mitre-table-container');
    if (mitreContainer) {
      const mitreList = rep.mitre_attack || [];
      if (mitreList.length === 0) {
        mitreContainer.innerHTML = `<div class="empty-state" style="height:60px;">No MITRE threat detections recorded for this period.</div>`;
      } else {
        mitreContainer.innerHTML = `
          <table style="width:100%;border-collapse:collapse;font-size:0.75rem;margin-top:0.5rem;">
            <thead>
              <tr style="text-align:left;border-bottom:1px solid var(--border);color:var(--text-dim);">
                <th style="padding:0.4rem;">Technique ID</th>
                <th style="padding:0.4rem;">Name</th>
                <th style="padding:0.4rem;">Severity</th>
                <th style="padding:0.4rem;">Detection Time</th>
              </tr>
            </thead>
            <tbody>
              ${mitreList.map(m => `
                <tr style="border-bottom:1px solid rgba(255,255,255,0.05);">
                  <td style="padding:0.4rem;font-family:var(--mono);color:var(--cyan);">${m.technique_id}</td>
                  <td style="padding:0.4rem;">${escapeHtml(m.technique_name)}</td>
                  <td style="padding:0.4rem;color:${m.severity === 'critical' || m.severity === 'high' ? 'var(--red)' : 'var(--amber)'};">${m.severity.toUpperCase()}</td>
                  <td style="padding:0.4rem;font-family:var(--mono);color:var(--text-dim);">${new Date(m.detection_time).toLocaleTimeString()}</td>
                </tr>
              `).join('')}
            </tbody>
          </table>
        `;
      }
    }
  } catch (_) {}
}

document.getElementById('report-date-select')?.addEventListener('change', (e) => {
  renderReport(e.target.value);
});

async function generateReportNow() {
  try {
    const res = await fetch(`${API_BASE}/reports/generate`, { method: 'POST' });
    const rep = await res.json();
    logToConsole(`[REPORTS] Generated report for date: ${rep.date}`, 'success');
    await loadReportsList();
    renderReport(rep.date);
  } catch (err) {
    logToConsole(`[REPORTS ERROR] ${err.message}`, 'danger');
  }
}

document.getElementById('btn-generate-report')?.addEventListener('click', generateReportNow);

document.getElementById('btn-download-pdf')?.addEventListener('click', () => {
  const sel = document.getElementById('report-date-select');
  if (sel?.value) window.open(`${API_BASE}/reports/${sel.value}/download?format=pdf`, '_blank');
});

document.getElementById('btn-download-csv')?.addEventListener('click', () => {
  const sel = document.getElementById('report-date-select');
  if (sel?.value) window.open(`${API_BASE}/reports/${sel.value}/download?format=csv`, '_blank');
});

document.getElementById('btn-download-json')?.addEventListener('click', () => {
  const sel = document.getElementById('report-date-select');
  if (sel?.value) window.open(`${API_BASE}/reports/${sel.value}/download?format=json`, '_blank');
});

// ── Browser & Extension Hub Controller ────────────────────────────────────
let discoveredProfiles = [];
let extensionDirectoryPath = '';

async function loadBrowserProfiles() {
  const grid = document.getElementById('browser-profiles-grid');
  const badge = document.getElementById('profiles-count-badge');
  const pathEl = document.getElementById('ext-absolute-path');

  try {
    const res = await fetch(`${API_BASE}/browser/profiles`);
    if (!res.ok) throw new Error('Failed to query profiles');
    const data = await res.json();
    discoveredProfiles = data.profiles || [];
    extensionDirectoryPath = data.extension_path || '';

    if (pathEl) pathEl.textContent = extensionDirectoryPath;

    const withEmail = discoveredProfiles.filter(p => p.email).length;
    if (badge) {
      badge.textContent = `${discoveredProfiles.length} Profiles Discovered (${withEmail} with Email IDs)`;
      badge.style.color = 'var(--cyan)';
    }

    if (!grid) return;
    grid.innerHTML = '';

    if (discoveredProfiles.length === 0) {
      grid.innerHTML = `
        <div class="empty-state">
          <span>🔍</span>
          <span>No browser profiles discovered automatically. Use the manual developer mode instructions below to load the extension folder.</span>
        </div>
      `;
      return;
    }

    discoveredProfiles.forEach(p => {
      const card = document.createElement('div');
      card.className = 'browser-card';

      let browserIcon = '🌐';
      let browserThemeClass = 'chrome';
      if (p.browser.toLowerCase().includes('edge')) {
        browserIcon = '🌊';
        browserThemeClass = 'edge';
      } else if (p.browser.toLowerCase().includes('brave')) {
        browserIcon = '🦁';
        browserThemeClass = 'brave';
      } else if (p.browser.toLowerCase().includes('opera')) {
        browserIcon = '🔴';
        browserThemeClass = 'opera';
      }

      card.innerHTML = `
        <div class="bcard-top">
          <div class="bcard-icon ${browserThemeClass}">${browserIcon}</div>
          <div class="bcard-info">
            <div class="bcard-name">${escapeHtml(p.display_name)}</div>
            <div class="bcard-browser">${escapeHtml(p.browser)} · <code>${escapeHtml(p.profile_dir)}</code></div>
          </div>
          <div class="bcard-status ${p.installed ? 'installed' : 'missing'}">${p.installed ? 'Ready' : 'Not Found'}</div>
        </div>

        <div class="bcard-email-box">
          <span class="email-label">Associated Email Account:</span>
          <div class="bcard-email-val ${p.email ? 'has-email' : 'no-email'}">
            <span>${p.email ? `✉ ${escapeHtml(p.email)}` : '👤 Local Profile (No signed-in email)'}</span>
          </div>
        </div>

        <div class="bcard-actions">
          <button class="btn-action primary btn-launch-browser" data-browser="${escapeHtml(p.browser)}" data-profile="${escapeHtml(p.profile_dir)}" ${!p.installed ? 'disabled' : ''}>
            🚀 1-Click Launch with Extension
          </button>
        </div>
      `;

      const launchBtn = card.querySelector('.btn-launch-browser');
      launchBtn?.addEventListener('click', async () => {
        const origText = launchBtn.innerHTML;
        launchBtn.disabled = true;
        launchBtn.innerHTML = '⏳ Launching Browser…';
        await launchBrowserProfile(p.browser, p.profile_dir);
        setTimeout(() => {
          launchBtn.disabled = false;
          launchBtn.innerHTML = origText;
        }, 3500);
      });

      grid.appendChild(card);
    });

  } catch (err) {
    if (badge) badge.textContent = 'Scan Error';
    if (grid) grid.innerHTML = `<div class="empty-state" style="color:var(--red);">Error loading browser accounts: ${err.message}</div>`;
  }
}

async function launchBrowserProfile(browserName, profileDir) {
  try {
    playCyberSound('beep');
    const res = await fetch(`${API_BASE}/browser/launch`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ browser: browserName, profile_dir: profileDir }),
    });
    const data = await res.json();
    if (res.ok && data.success) {
      logToConsole(`[BROWSER LAUNCH] Successfully launched ${browserName} [${profileDir}] with CryptoVeil extension.`, 'success');
      playCyberSound('success');
    } else {
      logToConsole(`[BROWSER LAUNCH ERROR] ${data.detail || data.error || 'Failed to launch'}`, 'danger');
      playCyberSound('threat');
    }
  } catch (err) {
    logToConsole(`[BROWSER LAUNCH EXCEPTION] ${err.message}`, 'danger');
  }
}

document.getElementById('btn-refresh-profiles')?.addEventListener('click', () => {
  loadBrowserProfiles();
  playCyberSound('beep');
});

document.getElementById('btn-copy-ext-path')?.addEventListener('click', () => {
  const path = extensionDirectoryPath || document.getElementById('ext-absolute-path')?.textContent;
  if (path) {
    navigator.clipboard.writeText(path);
    const btn = document.getElementById('btn-copy-ext-path');
    if (btn) {
      const orig = btn.innerHTML;
      btn.innerHTML = 'Copied Path! ✓';
      playCyberSound('success');
      setTimeout(() => { btn.innerHTML = orig; }, 2500);
    }
  }
});

// ── Modal / JSON Viewer ───────────────────────────────────────────────────
function openModal(title, jsonText) {
  if (!$eventModal || !$modalTitle || !$modalJson) return;
  $modalTitle.textContent = title;
  $modalJson.textContent = jsonText;
  $eventModal.style.display = 'flex';
}

document.getElementById('btn-close-modal')?.addEventListener('click', () => {
  if ($eventModal) $eventModal.style.display = 'none';
});

$eventModal?.addEventListener('click', (e) => {
  if (e.target === $eventModal) $eventModal.style.display = 'none';
});

// ── Status & Graph Refresh Poll ───────────────────────────────────────────
async function refreshStatus() {
  try {
    const r = await fetch(`${API_BASE}/status`);
    if (!r.ok) return;
    const st = await r.json();

    if (st.event_count !== undefined && st.event_count > totalEvents) {
      totalEvents = st.event_count;
      if ($evTotal) $evTotal.textContent = totalEvents;
    }
    if (st.checkpoints !== undefined && st.checkpoints > checkpoints) {
      checkpoints = st.checkpoints;
      if ($evCheckpoints) $evCheckpoints.textContent = checkpoints;
    }

    const extCount = st.websocket_clients?.extension || 0;
    if ($extStatusBadge) {
      if (extCount > 0) {
        $extStatusBadge.textContent = `${extCount} Extension${extCount > 1 ? 's' : ''} Connected`;
        $extStatusBadge.style.color = 'var(--green)';
        $extStatusBadge.style.borderColor = 'rgba(16, 185, 129, 0.4)';
      } else {
        $extStatusBadge.textContent = 'Extension Offline';
        $extStatusBadge.style.color = 'var(--text-dim)';
        $extStatusBadge.style.borderColor = 'var(--border)';
      }
    }

    const hubDot = document.getElementById('hub-status-dot');
    const hubTitle = document.getElementById('hub-status-title');
    const hubSub = document.getElementById('hub-status-sub');
    if (hubDot && hubTitle && hubSub) {
      if (extCount > 0) {
        hubDot.className = 'status-indicator-dot online';
        hubTitle.textContent = `Extension Attached (${extCount} Active)`;
        hubSub.textContent = 'Receiving real-time browser security telemetry';
      } else {
        hubDot.className = 'status-indicator-dot';
        hubTitle.textContent = 'Extension Bridge Offline';
        hubSub.textContent = 'Click "1-Click Launch" above or attach extension to start telemetry';
      }
    }
  } catch (_) {}
}

async function loadInitialEvents() {
  try {
    const r = await fetch(`${API_BASE}/events?limit=50`);
    if (!r.ok) return;
    const { events } = await r.json();
    if (events && events.length > 0) {
      events.forEach(ev => {
        eventBuffer.unshift(ev);
        if (ev.severity === 'critical' || ev.severity === 'high') {
          threatCount++;
        }
      });
      totalEvents = Math.max(totalEvents, events.length);
      if ($evTotal) $evTotal.textContent = totalEvents;
      if ($evThreats) $evThreats.textContent = threatCount;
      reapplyFilters();
    }
  } catch (_) {}
}

async function refreshGraph() {
  try {
    const r = await fetch(`${API_BASE}/process/graph`);
    if (!r.ok) return;
    const { nodes, edges } = await r.json();

    nodes.forEach(n => {
      if (!processNodes[n.pid]) {
        processNodes[n.pid] = n;
      } else {
        Object.assign(processNodes[n.pid], n);
      }
    });

    const apiPids = new Set(nodes.map(n => n.pid));
    Object.keys(processNodes).forEach(pid => {
      if (!apiPids.has(+pid)) delete processNodes[+pid];
    });

    processLinks = edges;
    updateGraph();
  } catch (_) {}
}

// ── Helpers ───────────────────────────────────────────────────────────────
function flashEl(el) {
  if (!el) return;
  el.classList.remove('flash');
  void el.offsetWidth;
  el.classList.add('flash');
}

function bumpStat(el, val) {
  if (!el) return;
  el.textContent = val;
  flashEl(el);
}

function escapeHtml(str) {
  return String(str || '').replace(/[&<>"']/g, m => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
  })[m]);
}

// ── Initialization ────────────────────────────────────────────────────────
initProcessGraph();
connectWebSocket();
loadInitialEvents();
refreshGraph();
refreshStatus();
loadBrowserProfiles();
fetchEventsChain();
loadReportsList();

setInterval(refreshGraph, 5000);
setInterval(refreshStatus, 3000);
