/* app.js — RIPPLE dual-mode frontend
 *
 * Modes:
 *   Replay Mode  — loads /api/replay/event-stream-2018 and animates the known funnel
 *   Live Scan    — connects to /api/scan/stream?package=NAME via SSE; builds graph live
 */
document.addEventListener('DOMContentLoaded', async () => {

  // ── DOM refs ──────────────────────────────────────────────
  const btnModeReplay  = document.getElementById('btn-mode-replay');
  const btnModeLive    = document.getElementById('btn-mode-live');
  const btnCompromise  = document.getElementById('btn-compromise');
  const liveControls   = document.getElementById('live-controls');
  const scanInput      = document.getElementById('scan-input');
  const btnScan        = document.getElementById('btn-scan');
  const terminalPane   = document.getElementById('terminal-pane');
  const terminalBody   = document.getElementById('terminal-body');
  const incidentBadge  = document.getElementById('incident-badge');

  const valInTree      = document.getElementById('val-intree');
  const valSemVer      = document.getElementById('val-semver');
  const valSymbol      = document.getElementById('val-symbol');
  const statInTree     = document.getElementById('stat-intree');
  const statSemVer     = document.getElementById('stat-semver');
  const statSymbol     = document.getElementById('stat-symbol');

  const panelPkgName     = document.getElementById('panel-pkg-name');
  const panelPkgVersion  = document.getElementById('panel-pkg-version');
  const panelStatusBadge = document.getElementById('panel-status-badge');
  const panelEvidenceList= document.getElementById('panel-evidence-list');
  const documentedImpact = document.getElementById('documented-impact');
  const sourceUrlEl      = document.getElementById('source-url');

  // ── Cytoscape setup ──────────────────────────────────────
  const cy = cytoscape({
    container: document.getElementById('cy'),
    elements: [],
    style: [
      {
        selector: 'node',
        style: {
          label:                 'data(label)',
          color:                 '#f1f5f9',
          'font-family':         'JetBrains Mono, monospace',
          'font-size':           10,
          'text-valign':         'center',
          'text-halign':         'center',
          'text-wrap':           'wrap',
          'background-color':    '#1e293b',
          'border-width':        2,
          'border-color':        '#334155',
          width:                 86,
          height:                86,
          'transition-property': 'background-color, border-color, width, height',
          'transition-duration': '350ms',
        }
      },
      { selector: 'node[colorClass = "source"]',
        style: { 'background-color': '#881337', 'border-color': '#f43f5e', 'border-width': 3,
          'shadow-blur': 26, 'shadow-color': 'rgba(244,63,94,.85)', 'shadow-opacity': 0.85,
          width: 94, height: 94 } },
      { selector: 'node[colorClass = "red"]',
        style: { 'background-color': '#dc2626', 'border-color': '#f87171',
          'shadow-blur': 22, 'shadow-color': 'rgba(239,68,68,.7)', 'shadow-opacity': 0.7 } },
      { selector: 'node[colorClass = "amber"]',
        style: { 'background-color': '#d97706', 'border-color': '#fbbf24',
          'shadow-blur': 14, 'shadow-color': 'rgba(245,158,11,.6)', 'shadow-opacity': 0.6 } },
      { selector: 'node[colorClass = "green"]',
        style: { 'background-color': '#059669', 'border-color': '#34d399',
          'shadow-blur': 8, 'shadow-color': 'rgba(16,185,129,.3)', 'shadow-opacity': 0.3 } },
      { selector: 'edge', style: {
          width: 2, 'line-color': '#334155', 'target-arrow-color': '#334155',
          'target-arrow-shape': 'triangle', 'curve-style': 'bezier', opacity: 0.55,
          'transition-property': 'line-color, target-arrow-color, width, opacity',
          'transition-duration': '300ms' } },
      { selector: 'edge.ripple', style: {
          'line-color': '#f43f5e', 'target-arrow-color': '#f43f5e', width: 3.5, opacity: 0.95 } },
    ],
    layout: { name: 'cose', animate: true, padding: 60,
      nodeRepulsion: () => 12000, idealEdgeLength: () => 140, numIter: 1000 },
  });

  // ── Node tap → show evidence ──────────────────────────────
  cy.on('tap', 'node', evt => showDetails(evt.target.data()));
  cy.on('tap', evt => { if (evt.target === cy) resetPanel(); });

  function colorClass(role, reachable) {
    if (role === 'compromise_source' || role === 'target') return 'source';
    if (reachable === true)  return 'red';
    if (reachable === null)  return 'amber';
    return 'green';
  }
  function statusText(role, reachable) {
    if (role === 'target')             return 'TARGET PACKAGE';
    if (role === 'compromise_source')  return 'COMPROMISE SOURCE';
    if (reachable === true)            return 'REACHABLE';
    if (reachable === null)            return 'UNKNOWN';
    return 'NOT REACHABLE';
  }

  function showDetails(d) {
    panelPkgName.textContent    = d.id;
    panelPkgVersion.textContent = `v${d.version || '?'}  ·  ${d.declared_range || ''}`;
    panelStatusBadge.style.display = 'inline-block';
    panelStatusBadge.className     = `status-badge ${d.colorClass}`;
    panelStatusBadge.textContent   = d.statusText;
    panelEvidenceList.innerHTML    = '';
    const evList = d.evidence && d.evidence.length ? d.evidence : ['No evidence recorded.'];
    evList.forEach(e => {
      const card = document.createElement('div');
      card.className   = 'evidence-card';
      card.textContent = e;
      panelEvidenceList.appendChild(card);
    });
  }

  function resetPanel() {
    panelPkgName.textContent    = 'Select a Node';
    panelPkgVersion.textContent = 'Click any package node to inspect evidence';
    panelStatusBadge.style.display = 'none';
    panelEvidenceList.innerHTML = '<div class="evidence-card muted">No package selected.</div>';
  }

  // ── Utility ───────────────────────────────────────────────
  function countUp(el, to, duration) {
    const start = Date.now();
    const tick = () => {
      const p = Math.min((Date.now() - start) / duration, 1);
      el.textContent = Math.round(p * to);
      if (p < 1) requestAnimationFrame(tick);
    };
    requestAnimationFrame(tick);
  }
  const delay = ms => new Promise(r => setTimeout(r, ms));

  function resetCounters() {
    [statInTree, statSemVer, statSymbol].forEach(s => s.classList.remove('active'));
    [valInTree, valSemVer, valSymbol].forEach(v => v.textContent = '—');
  }

  function activateCounters(inTree, semver, symbol) {
    statInTree.classList.add('active');  countUp(valInTree, inTree, 600);
    setTimeout(() => { statSemVer.classList.add('active'); countUp(valSemVer, semver, 600); }, 600);
    setTimeout(() => { statSymbol.classList.add('active'); countUp(valSymbol, symbol, 600); }, 1200);
  }

  // ── Add/update a node in cytoscape ───────────────────────
  function cyAddNode(id, label, version, role, reachable, evidence, declared_range) {
    const cc = colorClass(role, reachable);
    const st = statusText(role, reachable);
    const existing = cy.$(`#${CSS.escape(id)}`);
    if (existing.length) {
      existing.data({ colorClass: cc, statusText: st, reachable, evidence: evidence || [] });
    } else {
      cy.add({
        data: { id, label, version, role, symbol_reachable: reachable,
                declared_range, evidence: evidence || [], colorClass: cc, statusText: st }
      });
      cy.layout({ name: 'cose', animate: true, animationDuration: 600,
        padding: 60, nodeRepulsion: () => 10000, idealEdgeLength: () => 130, numIter: 600,
        fit: false }).run();
    }
  }

  function cyAddEdge(source, target) {
    const eid = `${source}->${target}`;
    if (!cy.$(`#${CSS.escape(eid)}`).length) {
      cy.add({ data: { id: eid, source, target } });
    }
  }

  // ══════════════════════════════════════════════════════════
  // REPLAY MODE
  // ══════════════════════════════════════════════════════════

  let replayData = null;

  async function loadReplay() {
    try {
      const res = await fetch('/api/replay/event-stream-2018');
      if (!res.ok) throw new Error(res.statusText);
      replayData = await res.json();
    } catch (e) {
      documentedImpact.textContent = `ERROR: ${e.message}`;
      return;
    }

    const href = replayData.historical_reference || {};
    documentedImpact.textContent = href.documented_impact || '';
    if (href.source_url) sourceUrlEl.href = href.source_url;

    // Build graph
    cy.elements().remove();
    const pkgs = replayData.packages || [];
    pkgs.forEach(pkg => {
      cyAddNode(
        pkg.name,
        (pkg.role === 'compromise_source' ? '⚠ ' : '') + pkg.name + '\nv' + pkg.version,
        pkg.version, pkg.role, pkg.symbol_reachable, pkg.evidence, pkg.declared_range
      );
    });
    pkgs.forEach(pkg => {
      if (pkg.name === 'event-stream') cyAddEdge('event-stream', 'flatmap-stream');
      else if (pkg.name !== 'flatmap-stream') cyAddEdge(pkg.name, 'event-stream');
    });
    cy.layout({ name: 'cose', animate: true, padding: 60,
      nodeRepulsion: () => 12000, idealEdgeLength: () => 140, numIter: 1000 }).run();
  }

  btnCompromise.addEventListener('click', async () => {
    if (!replayData) return;
    btnCompromise.disabled = true;
    resetCounters();
    cy.edges().removeClass('ripple');

    const fmNode = cy.$('#flatmap-stream');
    if (fmNode.length) {
      fmNode.animate({ style: { width: 120, height: 120 }}, { duration: 300 })
            .animate({ style: { width: 94,  height: 94  }}, { duration: 300 });
    }
    await delay(350);

    const consumers = (replayData.packages || []).filter(p => p.role !== 'compromise_source');
    const inTree       = consumers.filter(p => p.in_tree).length;
    const semverAdmits = consumers.filter(p => p.in_tree && p.semver_admits === true).length;
    const reachable    = consumers.filter(p => p.symbol_reachable === true).length;

    statInTree.classList.add('active'); countUp(valInTree, inTree, 600);
    await delay(400); cy.edges().addClass('ripple');
    await delay(800); statSemVer.classList.add('active'); countUp(valSemVer, semverAdmits, 600);
    await delay(900); statSymbol.classList.add('active'); countUp(valSymbol, reachable, 600);
    await delay(700);
    btnCompromise.disabled = false;
  });

  // ══════════════════════════════════════════════════════════
  // LIVE SCAN MODE
  // ══════════════════════════════════════════════════════════

  let currentEventSource = null;

  function termLine(text, cls = 'info') {
    const line = document.createElement('div');
    line.className = `term-line ${cls}`;
    line.textContent = text;
    terminalBody.appendChild(line);
    terminalBody.scrollTop = terminalBody.scrollHeight;
  }

  function clearTerminal() {
    terminalBody.innerHTML = '';
  }

  function startLiveScan(pkgName) {
    if (currentEventSource) { currentEventSource.close(); currentEventSource = null; }

    clearTerminal();
    termLine(`$ ripple scan ${pkgName}`, 'ok');
    cy.elements().remove();
    resetCounters();

    incidentBadge.textContent = `live scan: ${pkgName}`;
    incidentBadge.style.background = 'rgba(16,185,129,.12)';
    incidentBadge.style.color = '#6ee7b7';
    incidentBadge.style.borderColor = 'rgba(16,185,129,.25)';

    const url = `/api/scan/stream?package=${encodeURIComponent(pkgName)}`;
    const es = new EventSource(url);
    currentEventSource = es;

    es.addEventListener('log', e => {
      const d = JSON.parse(e.data);
      const levelMap = { info: 'info', ok: 'ok', warn: 'warn', danger: 'danger', error: 'error' };
      termLine(d.message, levelMap[d.level] || 'info');
    });

    es.addEventListener('node', e => {
      const d = JSON.parse(e.data);
      cyAddNode(d.id, d.label, d.version, d.role || 'consumer', null, [], '');
      // Add edge immediately if it's a consumer (they connect to the target)
    });

    es.addEventListener('edge', e => {
      const d = JSON.parse(e.data);
      cyAddEdge(d.source, d.target);
    });

    es.addEventListener('status', e => {
      const d = JSON.parse(e.data);
      const existing = cy.$(`#${CSS.escape(d.id)}`);
      if (existing.length) {
        const cc = colorClass('consumer', d.reachable);
        const st = statusText('consumer', d.reachable);
        existing.data({ colorClass: cc, statusText: st, symbol_reachable: d.reachable, evidence: d.evidence || [] });
      }
    });

    es.addEventListener('final', e => {
      const d = JSON.parse(e.data);
      if (d.counts) {
        activateCounters(d.counts.in_tree, d.counts.semver_admits, d.counts.symbol_reachable);
      }
      termLine('─────────────────────────────────────────────', 'muted');
      termLine(`Done. In tree: ${d.counts?.in_tree ?? '?'}  Semver admits: ${d.counts?.semver_admits ?? '?'}  Reachable: ${d.counts?.symbol_reachable ?? '?'}  Unknown: ${d.counts?.unknown ?? '?'}`, 'ok');
      es.close();
      currentEventSource = null;
      btnScan.disabled = false;
    });

    es.addEventListener('error', e => {
      if (e.data) {
        const d = JSON.parse(e.data);
        termLine(`ERROR: ${d.message}`, 'error');
      } else {
        termLine('Connection error or stream ended.', 'warn');
      }
      es.close();
      currentEventSource = null;
      btnScan.disabled = false;
    });

    es.onerror = () => {
      if (es.readyState === EventSource.CLOSED) {
        termLine('Stream closed.', 'muted');
        btnScan.disabled = false;
      }
    };
  }

  btnScan.addEventListener('click', () => {
    const pkg = scanInput.value.trim();
    if (!pkg) return;
    btnScan.disabled = true;
    startLiveScan(pkg);
  });

  scanInput.addEventListener('keydown', e => {
    if (e.key === 'Enter') btnScan.click();
  });

  // ══════════════════════════════════════════════════════════
  // MODE SWITCHING
  // ══════════════════════════════════════════════════════════

  function switchToReplay() {
    btnModeReplay.classList.add('active');
    btnModeLive.classList.remove('active');
    btnCompromise.style.display = '';
    liveControls.style.display = 'none';
    terminalPane.style.display = 'none';
    incidentBadge.textContent = 'event-stream · Nov 2018';
    incidentBadge.style.cssText = '';
    if (currentEventSource) { currentEventSource.close(); currentEventSource = null; }
    loadReplay();
  }

  function switchToLive() {
    btnModeLive.classList.add('active');
    btnModeReplay.classList.remove('active');
    btnCompromise.style.display = 'none';
    liveControls.style.display = '';
    terminalPane.style.display = 'flex';
    cy.elements().remove();
    resetCounters();
    documentedImpact.textContent =
      'Live Scan mode — type any npm package name above to discover its real dependents and check reachability via OSV.dev, npm registry, and deps.dev.';
    sourceUrlEl.href = '#';
    sourceUrlEl.textContent = 'npm registry →';
    sourceUrlEl.href = 'https://www.npmjs.com';
  }

  btnModeReplay.addEventListener('click', switchToReplay);
  btnModeLive.addEventListener('click', switchToLive);

  // ── Boot: load Replay Mode ────────────────────────────────
  await loadReplay();
});
