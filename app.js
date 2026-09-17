/* app.js — RIPPLE
 *
 * Two modes, one board:
 *   Replay  — fetches the cached event-stream/2018 case file once, then
 *             narrates it into the terminal and board client-side. No
 *             further network calls — works with the network off.
 *   Live    — opens an EventSource to /api/scan/stream and renders each
 *             log/node/edge/status event the instant it arrives, so the
 *             terminal line and the board change land together.
 */
document.addEventListener('DOMContentLoaded', () => {

  const reduceMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;

  // Cytoscape's stylesheet does not resolve CSS custom properties — read the
  // computed values once so the board matches the page's light/dark theme.
  const rootStyle = getComputedStyle(document.documentElement);
  const cssVar = name => rootStyle.getPropertyValue(name).trim();
  const C = {
    ink: cssVar('--ink'), inkSoft: cssVar('--ink-soft'),
    paper: cssVar('--paper'), paperRaised: cssVar('--paper-raised'), rule: cssVar('--rule-strong'),
    source: cssVar('--source'), sourceBg: cssVar('--source-bg'),
    reachable: cssVar('--reachable'), reachableBg: cssVar('--reachable-bg'),
    unknown: cssVar('--unknown'), unknownBg: cssVar('--unknown-bg'),
    safe: cssVar('--safe'),
  };

  // ── DOM refs ────────────────────────────────────────────────
  const tabReplay      = document.getElementById('tab-replay');
  const tabLive         = document.getElementById('tab-live');
  const controlsReplay  = document.getElementById('controls-replay');
  const controlsLive    = document.getElementById('controls-live');
  const btnRunReplay    = document.getElementById('btn-run-replay');
  const scanForm        = document.getElementById('scan-form');
  const scanInput       = document.getElementById('scan-input');
  const capInput        = document.getElementById('cap-input');
  const btnScan         = document.getElementById('btn-scan');
  const transcript       = document.getElementById('transcript');
  const caseSubject     = document.getElementById('case-subject');
  const emptyBoard      = document.getElementById('empty-board');

  const vInTree  = document.getElementById('v-intree');
  const vSemver  = document.getElementById('v-semver');
  const vReach   = document.getElementById('v-reach');
  const vUnknown = document.getElementById('v-unknown');
  const cellInTree  = document.getElementById('cell-intree');
  const cellSemver  = document.getElementById('cell-semver');
  const cellReach   = document.getElementById('cell-reach');
  const cellUnknown = document.getElementById('cell-unknown');
  const unknownInfo = document.getElementById('unknown-info');

  const modalOverlay = document.getElementById('modal-overlay');
  const dossierModal = document.getElementById('dossier-modal');
  const dossierClose = document.getElementById('dossier-close');
  const dossierName  = document.getElementById('dossier-name');
  const dossierMeta  = document.getElementById('dossier-meta');
  const dossierStamp = document.getElementById('dossier-stamp');
  const dossierBody  = document.getElementById('dossier-body');

  const footnoteText = document.getElementById('footnote-text');
  const footnoteLink = document.getElementById('footnote-link');

  // ── Cytoscape ───────────────────────────────────────────────
  const cy = cytoscape({
    container: document.getElementById('cy'),
    elements: [],
    style: [
      { selector: 'node', style: {
          label: 'data(label)', color: C.ink,
          'font-family': 'IBM Plex Mono, monospace', 'font-size': 10, 'font-weight': 500,
          'text-valign': 'center', 'text-halign': 'center', 'text-wrap': 'wrap', 'text-max-width': 84,
          'background-color': C.paperRaised,
          'border-width': 1.6, 'border-color': C.rule,
          shape: 'round-rectangle', width: 84, height: 60,
          'transition-property': 'background-color, border-color, width, height, border-style',
          'transition-duration': reduceMotion ? '0ms' : '260ms',
      }},
      { selector: 'node[state = "source"]', style: {
          'background-color': C.sourceBg, 'border-color': C.source, 'border-width': 3,
          shape: 'round-hexagon', width: 96, height: 72, color: C.source, 'font-weight': 700,
          'transition-property': 'background-color, border-color, width, height, border-style, border-width',
      }},
      { selector: 'node[state = "reachable"]', style: {
          'background-color': C.reachableBg, 'border-color': C.reachable, 'border-width': 2.5,
          shape: 'round-rectangle', color: C.reachable, 'font-weight': 600,
      }},
      { selector: 'node[state = "unknown"]', style: {
          'background-color': C.unknownBg, 'border-color': C.unknown, 'border-width': 2,
          'border-style': 'dashed', shape: 'round-diamond', width: 92, height: 68, color: C.unknown,
      }},
      { selector: 'node[state = "safe"]', style: {
          'background-color': C.paper, 'border-color': C.safe, 'border-width': 1.4,
          'border-style': 'dotted', shape: 'round-rectangle', color: C.inkSoft, opacity: 0.72,
      }},
      { selector: 'node.pending', style: { 'border-style': 'dashed', opacity: 0.6 } },
      { selector: 'edge', style: {
          width: 1.6, 'line-color': C.rule, 'line-style': 'dashed',
          'curve-style': 'bezier', 'target-arrow-shape': 'none', opacity: 0.65,
          'transition-property': 'line-color, width, opacity, line-style',
          'transition-duration': reduceMotion ? '0ms' : '220ms',
      }},
      { selector: 'edge[verdict = "reachable"]', style: {
          'line-color': C.reachable, width: 2.6, 'line-style': 'solid', opacity: 0.9,
      }},
      { selector: 'edge[verdict = "admits"]', style: {
          'line-color': C.unknown, width: 2, 'line-style': 'solid', opacity: 0.8,
      }},
      { selector: 'edge[verdict = "unknown"]', style: {
          'line-color': C.unknown, width: 1.6, 'line-style': 'dotted', opacity: 0.8,
      }},
      { selector: 'edge[verdict = "rejects"], edge[verdict = "safe"], edge[verdict = "not_declared"]', style: {
          'line-color': C.safe, width: 1.3, 'line-style': 'dotted', opacity: 0.55,
      }},
    ],
    layout: { name: 'preset' },
    minZoom: 0.25, maxZoom: 1.4,
    wheelSensitivity: 0.25,
  });

  // Debounced: addNode() calls this after every reveal, but starting a new
  // animated layout while the previous one is still animating leaves nodes
  // stranded mid-transition. Coalescing rapid calls into one keeps the
  // "live-settling" feel without the corruption. Plain 'cose' (bundled with
  // cytoscape core, no extension-loading edge cases) proved far more
  // reliable here than fcose for this incremental-reveal pattern.
  let layoutTimer = null;
  function runLayout() {
    if (layoutTimer) clearTimeout(layoutTimer);
    layoutTimer = setTimeout(() => {
      layoutTimer = null;
      const layout = cy.layout({
        name: 'cose', animate: !reduceMotion, animationDuration: 400,
        padding: 55, nodeRepulsion: () => 14000, idealEdgeLength: () => 160,
        numIter: 800, fit: true,
      });
      // cose fits to the whole graph's bounding box, which can leave the
      // compromise source off-centre once consumers cluster to one side.
      // Re-centre the viewport on it specifically once the layout settles,
      // without touching the zoom level fit() already chose.
      layout.one('layoutstop', () => {
        const sources = cy.nodes().filter(n => n.data('state') === 'source' || n.data('role') === 'target');
        if (sources.nonempty()) cy.center(sources);
      });
      layout.run();
    }, 90);
  }

  const cyContainer = document.getElementById('cy');
  cy.on('tap', 'node', evt => openDossier(evt.target.data(), cyContainer));
  cy.on('tap', evt => { if (evt.target === cy) closeDossier(); });

  // ── Terminal ────────────────────────────────────────────────
  let lineNo = 0;
  let userScrolledUp = false;
  transcript.addEventListener('scroll', () => {
    userScrolledUp = transcript.scrollTop + transcript.clientHeight < transcript.scrollHeight - 24;
  });

  function termLine(text, level = 'info') {
    lineNo += 1;
    const row = document.createElement('div');
    row.className = `transcript-line ${level}`;
    const no = document.createElement('span'); no.className = 'no'; no.textContent = String(lineNo).padStart(2, '0');
    const tx = document.createElement('span'); tx.className = 'tx'; tx.textContent = text;
    row.appendChild(no); row.appendChild(tx);
    transcript.appendChild(row);
    if (!userScrolledUp) transcript.scrollTop = transcript.scrollHeight;
    return row;
  }

  function clearTranscript() {
    transcript.innerHTML = '';
    lineNo = 0;
    userScrolledUp = false;
  }

  // ── Funnel ──────────────────────────────────────────────────
  function countUp(el, to, duration) {
    if (reduceMotion) { el.textContent = to; return; }
    const start = performance.now();
    const from = 0;
    const tick = now => {
      const p = Math.min((now - start) / duration, 1);
      el.textContent = Math.round(from + p * (to - from));
      if (p < 1) requestAnimationFrame(tick);
    };
    requestAnimationFrame(tick);
  }
  function resetFunnel() {
    [cellInTree, cellSemver, cellReach, cellUnknown].forEach(c => c.classList.remove('active'));
    [vInTree, vSemver, vReach, vUnknown].forEach(v => v.textContent = '—');
    unknownInfo.hidden = true;
  }
  function setFunnel(counts, unknownZeroReason) {
    cellInTree.classList.add('active');  countUp(vInTree,  counts.in_tree || 0, 500);
    cellSemver.classList.add('active');  countUp(vSemver,  counts.semver_admits || 0, 500);
    cellReach.classList.add('active');   countUp(vReach,   counts.symbol_reachable || 0, 500);
    cellUnknown.classList.add('active'); countUp(vUnknown, counts.unknown || 0, 500);
    if ((counts.unknown || 0) === 0 && unknownZeroReason) {
      unknownInfo.hidden = false;
      unknownInfo.title = unknownZeroReason;
    } else {
      unknownInfo.hidden = true;
    }
  }

  // ── Board node/edge helpers ────────────────────────────────
  function addNode(id, label, version, role) {
    if (cy.$id(id).nonempty()) return;
    emptyBoard.style.display = 'none';
    cy.add({ data: { id, label, version, role, state: role === 'target' || role === 'source' ? 'source' : 'pending', evidence: [], declared_range: '' } });
    runLayout();
  }

  // A brief "resolved" flourish on the compromise-source node(s) once an
  // investigation finishes settling — a soft border pulse, then still.
  function pulseSourceNodes() {
    if (reduceMotion) return;
    const sources = cy.nodes().filter(n => n.data('state') === 'source' || n.data('role') === 'target');
    sources.forEach(n => {
      const thick = { style: { 'border-width': 6 } };
      const thin = { style: { 'border-width': 3 } };
      n.animate(thick, { duration: 420, easing: 'ease-in-out-sine' })
        .animate(thin, { duration: 420, easing: 'ease-in-out-sine' })
        .animate(thick, { duration: 420, easing: 'ease-in-out-sine' })
        .animate(thin, { duration: 420, easing: 'ease-in-out-sine' });
    });
  }
  function setEdge(from, to, gate, verdict) {
    const eid = `${from}->${to}`;
    if (cy.$id(eid).empty()) {
      cy.add({ data: { id: eid, source: from, target: to, gate, verdict } });
    } else {
      cy.$id(eid).data({ gate, verdict });
    }
  }
  function setStatus(id, state, evidence, declaredRange) {
    const n = cy.$id(id);
    if (n.empty()) return;
    n.removeClass('pending');
    n.data('state', state);
    n.data('evidence', evidence || []);
    if (declaredRange !== undefined) n.data('declared_range', declaredRange);
  }

  function resetBoard() {
    cy.elements().remove();
    emptyBoard.style.display = 'flex';
    closeDossier();
  }

  // ── Dossier (evidence modal) ─────────────────────────────────
  const STAMP_LABEL = { source: 'Compromise source', reachable: 'Reachable', unknown: 'Unknown', safe: 'Filtered out' };
  let modalTriggerEl = null;

  function openDossier(d, triggerEl) {
    modalTriggerEl = triggerEl || document.activeElement;
    dossierName.textContent = d.id;
    dossierMeta.textContent = `v${d.version || '?'}${d.declared_range ? '  ·  declares: ' + d.declared_range : ''}`;
    if (d.state && STAMP_LABEL[d.state]) {
      dossierStamp.hidden = false;
      dossierStamp.className = `dossier-stamp ${d.state}`;
      dossierStamp.textContent = STAMP_LABEL[d.state];
    } else {
      dossierStamp.hidden = true;
    }
    renderExhibits(d.evidence || [], d.state);
    modalOverlay.hidden = false;
    requestAnimationFrame(() => {
      modalOverlay.classList.add('open');
      dossierModal.focus();
    });
    document.addEventListener('keydown', onModalKeydown);
  }

  function closeDossier() {
    if (modalOverlay.hidden) return;
    modalOverlay.classList.remove('open');
    document.removeEventListener('keydown', onModalKeydown);
    const finish = () => { modalOverlay.hidden = true; };
    if (reduceMotion) finish(); else setTimeout(finish, 220);
    if (modalTriggerEl && document.contains(modalTriggerEl)) modalTriggerEl.focus();
    modalTriggerEl = null;
  }

  function onModalKeydown(e) {
    if (e.key === 'Escape') { e.preventDefault(); closeDossier(); return; }
    if (e.key !== 'Tab') return;
    // Focus trap: cycle Tab/Shift+Tab within the modal's focusable elements.
    const focusables = dossierModal.querySelectorAll('button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])');
    if (!focusables.length) return;
    const first = focusables[0], last = focusables[focusables.length - 1];
    if (e.shiftKey && document.activeElement === first) { e.preventDefault(); last.focus(); }
    else if (!e.shiftKey && document.activeElement === last) { e.preventDefault(); first.focus(); }
  }

  dossierClose.addEventListener('click', closeDossier);
  modalOverlay.addEventListener('click', e => { if (e.target === modalOverlay) closeDossier(); });

  // ── Plain-language evidence copy ─────────────────────────────
  // The gate evidence strings are written to be machine-groupable (L1:/L2:/
  // L3: prefixes) as well as human-readable — we parse them here just to
  // pick a plain-English headline; the original strings still render below
  // as the technical trail, never replaced.
  const GATE_TITLE = { L1: 'L1 — in the dependency tree', L2: 'L2 — semver admits', L3: 'L3 — symbol reachable', OTHER: 'Notes' };

  function plainL1(lines) {
    if (!lines.length) return null;
    const text = lines.join(' ');
    if (/NOT IN TREE/.test(text)) return { q: 'Is it in the dependency tree?', a: `No — ${text.replace(/^L1:\s*NOT IN TREE\s*—\s*/, '')}` };
    // Any other L1 line (direct "IN TREE" or a transitive-consumer description)
    // is an affirmative — it's present in the graph one way or another.
    return { q: 'Is it in the dependency tree?', a: `Yes — ${text.replace(/^L1:\s*(IN TREE\s*—\s*)?/, '')}` };
  }
  function plainL2(lines) {
    const text = lines.join(' ');
    if (/ADMITS|INHERITED/.test(text)) return { q: 'Could it have received the compromised version?', a: `Yes — ${text.replace(/^L2:\s*(ADMITS|INHERITED)\s*—?\s*/, '')}` };
    if (/REJECTS/.test(text)) return { q: 'Could it have received the compromised version?', a: `No — ${text.replace(/^L2:\s*REJECTS\s*—\s*/, '')}` };
    if (/UNKNOWN/.test(text)) return { q: 'Could it have received the compromised version?', a: `Can't tell — ${text.replace(/^L2:\s*UNKNOWN\s*—\s*/, '')}` };
    return null;
  }
  function plainL3(lines) {
    const text = lines.join(' ');
    if (/REACHABLE(?!.*NOT)|UNCONDITIONAL/.test(text) && !/NOT REACHABLE/.test(text)) {
      return { q: 'Would the malicious code actually run?', a: 'Yes. The compromised code loads the moment the chain above it loads, with no conditions — so anything that reaches this package runs it too.' };
    }
    if (/UNKNOWN/.test(text)) {
      return { q: 'Would the malicious code actually run?', a: "Can't tell — a step in the chain couldn't be statically analysed (see the technical trail below), so this is marked unknown rather than guessed." };
    }
    return { q: 'Would the malicious code actually run?', a: 'No — the chain is broken or conditional somewhere before the compromised package, so this was filtered out as not exposed.' };
  }

  function renderExhibits(evidence, state) {
    dossierBody.innerHTML = '';
    if (!evidence.length) {
      dossierBody.innerHTML = '<div class="dossier-empty">No evidence recorded for this node.</div>';
      return;
    }
    const groups = { L1: [], L2: [], L3: [], OTHER: [] };
    evidence.forEach(line => {
      const m = /^L([123])[\s:]/.exec(line);
      if (m) groups[`L${m[1]}`].push(line); else groups.OTHER.push(line);
    });

    if (state === 'source') {
      const p = document.createElement('div'); p.className = 'plain-answer';
      p.innerHTML = '<div class="q">Why is this the compromise source?</div>'
        + `<div class="a">${groups.OTHER.map(escapeHtml).join('<br>')}</div>`;
      dossierBody.appendChild(p);
    } else {
      [plainL1(groups.L1), plainL2(groups.L2), plainL3(groups.L3)].forEach(entry => {
        if (!entry) return;
        const p = document.createElement('div'); p.className = 'plain-answer';
        p.innerHTML = `<div class="q">${escapeHtml(entry.q)}</div><div class="a">${escapeHtml(entry.a)}</div>`;
        dossierBody.appendChild(p);
      });
    }

    const trailHeader = document.createElement('div');
    trailHeader.className = 'tech-trail-toggle';
    trailHeader.textContent = 'Technical trail';
    dossierBody.appendChild(trailHeader);

    Object.keys(groups).forEach(k => {
      if (!groups[k].length) return;
      const g = document.createElement('div'); g.className = 'exhibit-group';
      const h = document.createElement('div'); h.className = 'exhibit-gate'; h.textContent = GATE_TITLE[k];
      g.appendChild(h);
      groups[k].forEach(line => {
        const e = document.createElement('div'); e.className = 'exhibit'; e.textContent = line;
        g.appendChild(e);
      });
      dossierBody.appendChild(g);
    });
  }

  function escapeHtml(s) {
    return s.replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  }

  const delay = ms => new Promise(r => setTimeout(r, reduceMotion ? 0 : ms));

  // ══════════════════════════════════════════════════════════
  // REPLAY MODE
  // ══════════════════════════════════════════════════════════

  let replayData = null;
  let replayRunning = false;

  async function loadReplayData() {
    try {
      const res = await fetch('/api/replay/event-stream-2018');
      if (!res.ok) throw new Error(res.statusText);
      replayData = await res.json();
    } catch (e) {
      termLine(`Could not load the cached case file: ${e.message}`, 'warn');
      return;
    }
    footnoteText.textContent = (replayData.historical_reference || {}).documented_impact || '';
    if (replayData.historical_reference && replayData.historical_reference.source_url) {
      footnoteLink.href = replayData.historical_reference.source_url;
    }
  }

  async function playReplay() {
    if (!replayData || replayRunning) return;
    replayRunning = true;
    btnRunReplay.disabled = true;
    document.body.classList.add('is-scanning');
    clearTranscript();
    resetBoard();
    resetFunnel();

    const pkgs = replayData.packages || [];
    const byName = Object.fromEntries(pkgs.map(p => [p.name, p]));

    termLine('Opening cached case file: event-stream@3.3.6 (npm, Nov 2018).', 'ok');
    await delay(150);

    // Sources first
    for (const src of pkgs.filter(p => p.role === 'compromise_source')) {
      termLine(`Source: ${src.name}@${src.version} — ${src.evidence[0] || 'compromise source'}`, 'risk');
      addNode(src.name, `${src.name}\nv${src.version}`, src.version, 'source');
      setStatus(src.name, 'source', src.evidence, src.declared_range);
      await delay(180);
    }
    setEdge('event-stream', 'flatmap-stream', 'L3', 'reachable');

    const consumers = pkgs.filter(p => p.role !== 'compromise_source');
    termLine(`Walking the dependency graph for ${consumers.length} known consumers…`, 'info');
    await delay(220);

    let inTree = 0, semverAdmits = 0, reachable = 0, unknown = 0;

    for (const c of consumers) {
      termLine(`Resolving ${c.name}@${c.version}…`, 'info');
      addNode(c.name, `${c.name}\nv${c.version}`, c.version, 'consumer');
      // A transitive consumer's real edge is to its intermediate (e.g.
      // nodemon -> ps-tree), not straight to event-stream — that misrepresents
      // the actual path the malicious code would travel.
      const edgeTarget = c.transitive_via ? c.transitive_via.name : 'event-stream';
      if (c.transitive_via) addNode(c.transitive_via.name, `${c.transitive_via.name}\nv${c.transitive_via.version}`, c.transitive_via.version, 'consumer');
      setEdge(c.name, edgeTarget, 'L1', c.in_tree ? 'in_tree' : 'not_declared');
      await delay(160);

      if (c.in_tree) inTree += 1;
      const l2 = c.semver_admits === true ? 'ADMITS' : c.semver_admits === false ? 'REJECTS' : 'UNKNOWN';
      if (c.transitive_via) {
        termLine(
          `  L2 — inherited: ${c.declared_range.replace(/^TRANSITIVE via /, '')} declares '~3.3.0', `
          + `which ${l2} event-stream@3.3.6.`,
          c.semver_admits ? 'risk' : 'info',
        );
      } else {
        termLine(`  L2 — declared range "${c.declared_range}" ${l2} event-stream@3.3.6.`, c.semver_admits ? 'risk' : 'info');
      }
      if (c.semver_admits === true) { semverAdmits += 1; setEdge(c.name, edgeTarget, 'L2', 'admits'); }
      else if (c.semver_admits === false) setEdge(c.name, edgeTarget, 'L2', 'rejects');
      await delay(160);

      let state;
      const chainNote = c.transitive_via ? ` chain walk: ${c.name} → ${c.transitive_via.name} → event-stream → flatmap-stream.` : '';
      if (c.symbol_reachable === true) { state = 'reachable'; reachable += 1; setEdge(c.name, edgeTarget, 'L3', 'reachable');
        termLine(`  L3 —${chainNote} All hops unconditional. REACHABLE.`, 'risk'); }
      else if (c.symbol_reachable === null) { state = 'unknown'; unknown += 1; setEdge(c.name, edgeTarget, 'L3', 'unknown');
        termLine(`  L3 —${chainNote} A hop could not be statically determined. UNKNOWN.`, 'warn'); }
      else { state = 'safe'; setEdge(c.name, edgeTarget, 'L3', 'safe');
        termLine(`  L3 —${chainNote} Not reachable. Filtered out.`, 'ok'); }
      setStatus(c.name, state, c.evidence, c.declared_range);
      await delay(220);
    }

    termLine(`Investigation complete. In tree ${inTree} · Admits ${semverAdmits} · Reachable ${reachable} · Unknown ${unknown}.`, 'ok');
    if (unknown === 0) {
      termLine(
        'Unknown 0 — every hop in this case is documented in npm’s postmortem, so no hop required a guess. '
        + 'That will not hold for most packages: try Live Scan.',
        'muted',
      );
    }
    setFunnel(
      { in_tree: inTree, semver_admits: semverAdmits, symbol_reachable: reachable, unknown },
      'Every hop in this documented incident is confirmed in npm’s postmortem — none required a guess. Live Scan will show real unknowns.',
    );
    pulseSourceNodes();

    replayRunning = false;
    btnRunReplay.disabled = false;
    document.body.classList.remove('is-scanning');
  }

  btnRunReplay.addEventListener('click', playReplay);

  // ══════════════════════════════════════════════════════════
  // LIVE SCAN MODE
  // ══════════════════════════════════════════════════════════

  let currentSource = null;

  function closeLiveStream() {
    if (currentSource) { currentSource.close(); currentSource = null; }
    btnScan.disabled = false;
    document.body.classList.remove('is-scanning');
    pulseSourceNodes();
  }

  function offerSimulate(pkgName) {
    const wrap = document.createElement('div');
    wrap.className = 'simulate-offer';
    wrap.innerHTML = `<p>No known vulnerabilities for <strong>${pkgName}</strong>. Simulate a hypothetical compromise to see the blast radius?</p>`;
    const btn = document.createElement('button');
    btn.className = 'btn btn-risk btn-sm';
    btn.textContent = 'Simulate compromise';
    btn.addEventListener('click', () => { wrap.remove(); startLiveScan(pkgName, 'simulate'); });
    wrap.appendChild(btn);
    transcript.appendChild(wrap);
    if (!userScrolledUp) transcript.scrollTop = transcript.scrollHeight;
  }

  function startLiveScan(pkgName, mode) {
    closeLiveStream();
    clearTranscript();
    resetBoard();
    resetFunnel();
    btnScan.disabled = true;
    document.body.classList.add('is-scanning');

    caseSubject.textContent = mode === 'simulate' ? `${pkgName} (simulated)` : pkgName;
    caseSubject.className = mode === 'simulate' ? 'v sim' : 'v';

    termLine(`$ ripple investigate ${pkgName}${mode === 'simulate' ? ' --simulate' : ''}`, 'ok');

    const cap = capInput.value || 25;
    const url = `/api/scan/stream?package=${encodeURIComponent(pkgName)}&mode=${mode}&limit=${cap}`;
    const es = new EventSource(url);
    currentSource = es;

    es.addEventListener('log', e => {
      const d = JSON.parse(e.data);
      termLine(d.text, d.level || 'info');
    });

    es.addEventListener('node', e => {
      const d = JSON.parse(e.data);
      addNode(d.id, d.label, d.version, d.role);
    });

    es.addEventListener('edge', e => {
      const d = JSON.parse(e.data);
      setEdge(d.from, d.to, d.gate, d.verdict);
    });

    es.addEventListener('status', e => {
      const d = JSON.parse(e.data);
      const node = cy.$id(d.id);
      const declaredRange = node.nonempty() ? node.data('declared_range') : '';
      setStatus(d.id, d.state, d.evidence, declaredRange);
    });

    es.addEventListener('final', e => {
      const d = JSON.parse(e.data);
      if (d.error) {
        termLine(`Stopped: ${d.error}`, 'warn');
      } else if (d.no_advisories) {
        offerSimulate(d.package);
      } else if (d.counts) {
        setFunnel(d.counts);
        // backfill declared_range onto nodes from the final package list, for the dossier
        (d.packages || []).forEach(p => {
          const n = cy.$id(p.name);
          if (n.nonempty() && p.declared_range) n.data('declared_range', p.declared_range);
        });
      }
      closeLiveStream();
    });

    es.onerror = () => {
      if (es.readyState === EventSource.CLOSED) {
        termLine('Connection closed.', 'muted');
        closeLiveStream();
      }
    };
  }

  scanForm.addEventListener('submit', e => {
    e.preventDefault();
    const pkg = scanInput.value.trim();
    if (!pkg) return;
    startLiveScan(pkg, 'real');
  });

  // ══════════════════════════════════════════════════════════
  // MODE SWITCHING
  // ══════════════════════════════════════════════════════════

  const mainStack = document.querySelector('.main-stack');

  function activateTab(tab) {
    [tabReplay, tabLive].forEach(t => t.classList.remove('active'));
    tab.classList.add('active');
  }

  // A short cross-fade so the mode switch reads as a deliberate transition,
  // not an instant swap. Reduced-motion viewers get the end state directly.
  function withModeFade(applyChanges) {
    if (reduceMotion) { applyChanges(); return; }
    mainStack.classList.add('mode-switching');
    setTimeout(() => {
      applyChanges();
      requestAnimationFrame(() => mainStack.classList.remove('mode-switching'));
    }, 160);
  }

  function switchToReplay() {
    activateTab(tabReplay);
    withModeFade(() => {
      controlsReplay.style.display = '';
      controlsLive.style.display = 'none';
      closeLiveStream();
      caseSubject.textContent = 'event-stream@3.3.6';
      caseSubject.className = 'v';
      footnoteLink.href = 'https://blog.npmjs.org/post/180565383195/details-about-the-event-stream-incident';
      footnoteLink.textContent = "npm's incident write-up";
      resetBoard();
      resetFunnel();
      clearTranscript();
      playReplay();
    });
  }

  function switchToLive() {
    activateTab(tabLive);
    withModeFade(() => {
      controlsReplay.style.display = 'none';
      controlsLive.style.display = '';
      resetBoard();
      resetFunnel();
      clearTranscript();
      caseSubject.textContent = '—';
      termLine('Enter an npm package name above and press Investigate.', 'muted');
      footnoteText.textContent = 'Live scan queries the real npm registry, OSV.dev and ecosyste.ms — nothing here is pre-scripted.';
      footnoteLink.href = 'https://osv.dev';
      footnoteLink.textContent = 'about OSV.dev';
      scanInput.focus();
    });
  }

  tabReplay.addEventListener('click', switchToReplay);
  tabLive.addEventListener('click', switchToLive);

  // ── Boot ───────────────────────────────────────────────────
  (async () => {
    await loadReplayData();
    await playReplay();
  })();
});
