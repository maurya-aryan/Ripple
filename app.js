/* app.js — RIPPLE frontend
 * Reads data/funnel_result.json, renders Cytoscape force-directed graph,
 * animates the compromise ripple on button click, computes and displays top funnel counters,
 * styles compromise sources distinctly, and displays evidence per node.
 */
document.addEventListener('DOMContentLoaded', async () => {
  // ── DOM refs ──────────────────────────────────────────────
  const btnCompromise    = document.getElementById('btn-compromise');
  const valInTree        = document.getElementById('val-intree');
  const valSemVer        = document.getElementById('val-semver');
  const valSymbol        = document.getElementById('val-symbol');
  const statInTree       = document.getElementById('stat-intree');
  const statSemVer       = document.getElementById('stat-semver');
  const statSymbol       = document.getElementById('stat-symbol');
  const panelPkgName     = document.getElementById('panel-pkg-name');
  const panelPkgVersion  = document.getElementById('panel-pkg-version');
  const panelStatusBadge = document.getElementById('panel-status-badge');
  const panelEvidenceList= document.getElementById('panel-evidence-list');
  const documentedImpact = document.getElementById('documented-impact');
  const sourceUrlEl      = document.getElementById('source-url');

  // ── Load data ─────────────────────────────────────────────
  let funnelData;
  try {
    const res = await fetch('data/funnel_result.json');
    if (!res.ok) throw new Error(res.statusText);
    funnelData = await res.json();
  } catch (err) {
    if (documentedImpact) {
      documentedImpact.textContent =
        'ERROR: Could not load data/funnel_result.json — run build_data.py and reachability/scan.py first.';
    }
    console.error(err);
    return;
  }

  // ── Footer (Fix 4: Reframe & citation) ──────────────────────
  const href = funnelData.historical_reference || {};
  if (href.documented_impact && documentedImpact) {
    documentedImpact.textContent = href.documented_impact;
  }
  if (href.source_url && sourceUrlEl) {
    sourceUrlEl.href = href.source_url;
  }

  // ── Build Cytoscape elements (Fix 3: Distinct role & styling) ──
  const packages = funnelData.packages || [];

  const nodeColor = pkg => {
    if (pkg.role === 'compromise_source') return 'source';
    if (pkg.symbol_reachable === true)    return 'red';
    if (pkg.symbol_reachable === null)    return 'amber';
    return 'green';
  };

  const nodeStatus = pkg => {
    if (pkg.role === 'compromise_source') {
      return pkg.name === 'flatmap-stream' ? 'PATIENT ZERO (Malicious Payload)' : 'COMPROMISE SOURCE (Injected Root)';
    }
    if (pkg.symbol_reachable === true)    return 'REACHABLE (Exposed)';
    if (pkg.symbol_reachable === null)    return 'UNKNOWN (Unanalysable)';
    return 'FILTERED OUT (Safe)';
  };

  const nodes = packages.map(pkg => ({
    data: {
      id:              pkg.name,
      label:           (pkg.role === 'compromise_source' ? '⚠ ' : '') + pkg.name + '\nv' + pkg.version,
      version:         pkg.version,
      role:            pkg.role || 'consumer',
      declared_range:  pkg.declared_range,
      semver_admits:   pkg.semver_admits,
      symbol_reachable:pkg.symbol_reachable,
      evidence:        pkg.evidence || [],
      colorClass:      nodeColor(pkg),
      statusText:      nodeStatus(pkg),
    }
  }));

  // Edges: event-stream → flatmap-stream;  consumers → event-stream
  const edges = [];
  packages.forEach(pkg => {
    if (pkg.name === 'event-stream') {
      edges.push({ data: { id: 'es->fm', source: 'event-stream', target: 'flatmap-stream' }});
    } else if (pkg.name !== 'flatmap-stream') {
      edges.push({ data: { id: pkg.name + '->es', source: pkg.name, target: 'event-stream' }});
    }
  });

  // ── Cytoscape init ────────────────────────────────────────
  const cy = cytoscape({
    container: document.getElementById('cy'),
    elements: { nodes, edges },
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
          'transition-duration': '300ms',
        }
      },
      // Distinct compromise source styling (Fix 3)
      {
        selector: 'node[colorClass = "source"]',
        style: {
          'background-color': '#881337',
          'border-color':     '#f43f5e',
          'border-width':     3,
          'shadow-blur':      26,
          'shadow-color':     'rgba(244,63,94,.85)',
          'shadow-opacity':   0.85,
          width:              94,
          height:             94,
        }
      },
      {
        selector: 'node[colorClass = "red"]',
        style: {
          'background-color': '#dc2626',
          'border-color':     '#f87171',
          'shadow-blur':      22,
          'shadow-color':     'rgba(239,68,68,.7)',
          'shadow-opacity':   0.7,
        }
      },
      {
        selector: 'node[colorClass = "amber"]',
        style: {
          'background-color': '#d97706',
          'border-color':     '#fbbf24',
          'shadow-blur':      14,
          'shadow-color':     'rgba(245,158,11,.6)',
          'shadow-opacity':   0.6,
        }
      },
      {
        selector: 'node[colorClass = "green"]',
        style: {
          'background-color': '#059669',
          'border-color':     '#34d399',
          'shadow-blur':      8,
          'shadow-color':     'rgba(16,185,129,.3)',
          'shadow-opacity':   0.3,
        }
      },
      {
        selector: 'edge',
        style: {
          width:                  2,
          'line-color':           '#334155',
          'target-arrow-color':   '#334155',
          'target-arrow-shape':   'triangle',
          'curve-style':          'bezier',
          opacity:                0.55,
          'transition-property':  'line-color, target-arrow-color, width, opacity',
          'transition-duration':  '300ms',
        }
      },
      {
        selector: 'edge.ripple',
        style: {
          'line-color':         '#f43f5e',
          'target-arrow-color': '#f43f5e',
          width:                3.5,
          opacity:              0.95,
        }
      },
    ],
    layout: {
      name: 'cose',
      animate: true,
      padding: 60,
      nodeRepulsion:   () => 12000,
      idealEdgeLength: () => 140,
      numIter: 1000,
    }
  });

  // ── Node tap → show evidence ──────────────────────────────
  cy.on('tap', 'node', evt => showDetails(evt.target.data()));
  cy.on('tap', evt => {
    if (evt.target === cy) resetPanel();
  });

  function showDetails(d) {
    panelPkgName.textContent    = d.id;
    panelPkgVersion.textContent = `v${d.version}  ·  declared: ${d.declared_range || 'N/A'}`;

    panelStatusBadge.style.display = 'inline-block';
    panelStatusBadge.className     = `status-badge ${d.colorClass}`;
    panelStatusBadge.textContent   = d.statusText;

    panelEvidenceList.innerHTML = '';
    (d.evidence && d.evidence.length ? d.evidence : ['No evidence recorded.'])
      .forEach(e => {
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
    panelEvidenceList.innerHTML = '<div class="evidence-card muted">No package selected. Click a node to view evidence.</div>';
  }

  // ── Count-up animation ────────────────────────────────────
  function countUp(el, to, duration) {
    const start = Date.now();
    const tick = () => {
      const progress = Math.min((Date.now() - start) / duration, 1);
      el.textContent = Math.round(progress * to);
      if (progress < 1) requestAnimationFrame(tick);
    };
    requestAnimationFrame(tick);
  }

  const delay = ms => new Promise(r => setTimeout(r, ms));

  // ── Compromise button (Fix 2 & Fix 3: Aggregate consumer counts) ──
  btnCompromise.addEventListener('click', async () => {
    btnCompromise.disabled = true;

    // Reset counters
    [statInTree, statSemVer, statSymbol].forEach(s => s.classList.remove('active'));
    [valInTree, valSemVer, valSymbol].forEach(v => v.textContent = '0');
    cy.edges().removeClass('ripple');

    // Filter out compromise sources (Fix 3) and compute consumer funnel counts (Fix 2)
    const consumers = packages.filter(p => p.role !== 'compromise_source');
    const inTree = consumers.filter(p => p.in_tree).length;
    const semverAdmits = consumers.filter(p => p.in_tree && p.semver_admits === true).length;
    const symbolReachable = consumers.filter(p => p.symbol_reachable === true).length;

    // Pulse the flatmap-stream node (patient zero)
    const fmNode = cy.$('#flatmap-stream');
    if (fmNode.length) {
      fmNode.animate({ style: { width: 120, height: 120 }}, { duration: 300 })
            .animate({ style: { width: 94,  height: 94  }}, { duration: 300 });
    }

    await delay(350);

    // Step 1 — L1 in_tree
    statInTree.classList.add('active');
    countUp(valInTree, inTree, 600);

    // Animate all edges (ripple outward)
    await delay(400);
    cy.edges().addClass('ripple');

    // Step 2 — L2 semver_admits
    await delay(800);
    statSemVer.classList.add('active');
    countUp(valSemVer, semverAdmits, 600);

    // Step 3 — L3 symbol_reachable
    await delay(900);
    statSymbol.classList.add('active');
    countUp(valSymbol, symbolReachable, 600);

    await delay(700);
    btnCompromise.disabled = false;
  });
});
