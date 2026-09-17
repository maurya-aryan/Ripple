document.addEventListener('DOMContentLoaded', async () => {
  let cy = null;
  let funnelData = null;

  // DOM Elements
  const btnCompromise = document.getElementById('btn-compromise');
  const valInTree = document.getElementById('val-intree');
  const valSemVer = document.getElementById('val-semver');
  const valSymbol = document.getElementById('val-symbol');

  const statInTree = document.getElementById('stat-intree');
  const statSemVer = document.getElementById('stat-semver');
  const statSymbol = document.getElementById('stat-symbol');

  const sidePanel = document.getElementById('side-panel');
  const panelPkgName = document.getElementById('panel-pkg-name');
  const panelPkgVersion = document.getElementById('panel-pkg-version');
  const panelStatusBadge = document.getElementById('panel-status-badge');
  const panelEvidenceList = document.getElementById('panel-evidence-list');

  const documentedImpact = document.getElementById('documented-impact');
  const sourceUrl = document.getElementById('source-url');

  // Load Funnel Result JSON (try data/funnel_result.json first, fallback to mock if running before integration)
  async function loadData() {
    try {
      const res = await fetch('data/funnel_result.json');
      if (!res.ok) throw new Error('Data file not found');
      return await res.json();
    } catch (e) {
      console.log('Fallback to local mock data:', e);
      const res = await fetch('frontend/mock/funnel_result.json');
      return await res.json();
    }
  }

  funnelData = await loadData();

  // Populate Footer
  if (funnelData.historical_reference) {
    documentedImpact.textContent = funnelData.historical_reference.documented_impact || '';
    if (funnelData.historical_reference.source_url) {
      sourceUrl.href = funnelData.historical_reference.source_url;
    }
  }

  // Build Graph Nodes & Edges
  const nodes = [];
  const edges = [];

  const packages = funnelData.packages || [];
  
  packages.forEach(pkg => {
    let colorClass = 'green';
    let statusText = 'SAFE (Filtered Out)';

    if (pkg.symbol_reachable === true) {
      colorClass = 'red';
      statusText = 'REACHABLE (Compromised)';
    } else if (pkg.symbol_reachable === null) {
      colorClass = 'amber';
      statusText = 'UNKNOWN (Unanalysable)';
    }

    nodes.push({
      data: {
        id: pkg.package,
        label: `${pkg.package}\nv${pkg.version}`,
        version: pkg.version,
        declared_range: pkg.declared_range,
        semver_admits: pkg.semver_admits,
        symbol_reachable: pkg.symbol_reachable,
        evidence: pkg.evidence || [],
        colorClass: colorClass,
        statusText: statusText
      }
    });
  });

  // Construct edges: event-stream -> flatmap-stream, and dependent packages -> event-stream / flatmap-stream
  packages.forEach(pkg => {
    if (pkg.package === 'event-stream') {
      edges.push({
        data: {
          id: 'event-stream->flatmap-stream',
          source: 'event-stream',
          target: 'flatmap-stream'
        }
      });
    } else if (pkg.package !== 'flatmap-stream') {
      // Connect to event-stream or flatmap-stream
      edges.push({
        data: {
          id: `${pkg.package}->event-stream`,
          source: pkg.package,
          target: 'event-stream'
        }
      });
    }
  });

  // Initialize Cytoscape
  cy = cytoscape({
    container: document.getElementById('cy'),
    elements: { nodes, edges },
    style: [
      {
        selector: 'node',
        style: {
          'label': 'data(label)',
          'color': '#f3f4f6',
          'font-family': 'JetBrains Mono, monospace',
          'font-size': '11px',
          'text-valign': 'center',
          'text-halign': 'center',
          'text-wrap': 'wrap',
          'background-color': '#1f2937',
          'border-width': 2,
          'border-color': '#4b5563',
          'width': 90,
          'height': 90,
          'transition-property': 'background-color, border-color, bounds',
          'transition-duration': '0.3s'
        }
      },
      {
        selector: 'node[colorClass = "red"]',
        style: {
          'background-color': '#ef4444',
          'border-color': '#f87171',
          'shadow-blur': 25,
          'shadow-color': 'rgba(239, 68, 68, 0.8)',
          'shadow-opacity': 0.8
        }
      },
      {
        selector: 'node[colorClass = "amber"]',
        style: {
          'background-color': '#f59e0b',
          'border-color': '#fbbf24',
          'shadow-blur': 15,
          'shadow-color': 'rgba(245, 158, 11, 0.6)',
          'shadow-opacity': 0.6
        }
      },
      {
        selector: 'node[colorClass = "green"]',
        style: {
          'background-color': '#10b981',
          'border-color': '#34d399',
          'shadow-blur': 10,
          'shadow-color': 'rgba(16, 185, 129, 0.4)',
          'shadow-opacity': 0.4
        }
      },
      {
        selector: 'edge',
        style: {
          'width': 2,
          'line-color': '#374151',
          'target-arrow-color': '#374151',
          'target-arrow-shape': 'triangle',
          'curve-style': 'bezier',
          'opacity': 0.6
        }
      },
      {
        selector: '.ripple-active',
        style: {
          'line-color': '#ef4444',
          'target-arrow-color': '#ef4444',
          'width': 4,
          'opacity': 1
        }
      }
    ],
    layout: {
      name: 'cose',
      animate: true,
      padding: 50,
      nodeRepulsion: function( node ){ return 8000; },
      idealEdgeLength: function( edge ){ return 120; }
    }
  });

  // Node Selection Handler
  cy.on('tap', 'node', (evt) => {
    const data = evt.target.data();
    showNodeDetails(data);
  });

  function showNodeDetails(data) {
    panelPkgName.textContent = data.id;
    panelPkgVersion.textContent = `Version ${data.version} (declared range: ${data.declared_range || 'N/A'})`;

    panelStatusBadge.style.display = 'inline-block';
    panelStatusBadge.className = `status-badge ${data.colorClass}`;
    panelStatusBadge.textContent = data.statusText;

    panelEvidenceList.innerHTML = '';
    if (data.evidence && data.evidence.length > 0) {
      data.evidence.forEach(ev => {
        const card = document.createElement('div');
        card.className = 'evidence-card';
        card.textContent = ev;
        panelEvidenceList.appendChild(card);
      });
    } else {
      panelEvidenceList.innerHTML = '<div class="evidence-card">No evidence available.</div>';
    }
  }

  // Count Up Animation
  function animateValue(obj, start, end, duration) {
    let startTimestamp = null;
    const step = (timestamp) => {
      if (!startTimestamp) startTimestamp = timestamp;
      const progress = Math.min((timestamp - startTimestamp) / duration, 1);
      obj.textContent = Math.floor(progress * (end - start) + start);
      if (progress < 1) {
        window.requestAnimationFrame(step);
      }
    };
    window.requestAnimationFrame(step);
  }

  // Button Click: Compromise Ripple Animation & Sequence Reveal
  btnCompromise.addEventListener('click', async () => {
    btnCompromise.disabled = true;
    btnCompromise.style.opacity = '0.6';

    const counts = funnelData.counts || { in_tree: 8, semver_admits: 4, symbol_reachable: 1 };

    // Reset stats UI
    statInTree.classList.remove('active');
    statSemVer.classList.remove('active');
    statSymbol.classList.remove('active');
    valInTree.textContent = '0';
    valSemVer.textContent = '0';
    valSymbol.textContent = '0';

    // Highlight flatmap-stream (patient zero)
    const flatmapNode = cy.$('#flatmap-stream');
    if (flatmapNode) {
      flatmapNode.animate({
        style: { 'width': 120, 'height': 120 }
      }, { duration: 400 }).animate({
        style: { 'width': 90, 'height': 90 }
      }, { duration: 400 });
    }

    // Step 1: Reveal in_tree
    await new Promise(r => setTimeout(r, 400));
    statInTree.classList.add('active');
    animateValue(valInTree, 0, counts.in_tree || 8, 800);

    // Animate edges
    cy.edges().addClass('ripple-active');

    // Step 2: Reveal semver_admits
    await new Promise(r => setTimeout(r, 1200));
    statSemVer.classList.add('active');
    animateValue(valSemVer, 0, counts.semver_admits || 4, 800);

    // Step 3: Reveal symbol_reachable
    await new Promise(r => setTimeout(r, 1200));
    statSymbol.classList.add('active');
    animateValue(valSymbol, 0, counts.symbol_reachable || 1, 800);

    await new Promise(r => setTimeout(r, 800));
    btnCompromise.disabled = false;
    btnCompromise.style.opacity = '1';
  });
});
