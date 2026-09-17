# RIPPLE
### Reachability, not just presence.

When an open-source package is compromised, existing tools flag every application that has it anywhere in their dependency tree. Most of those alerts are noise — the compromised code was never in a position to execute. RIPPLE finds the ones that actually matter.

---

## What it does

RIPPLE answers one question: **can this compromised code actually run in my application?**

It does this with a three-gate funnel:

| Gate | Question | What existing tools do |
|------|----------|----------------------|
| L1 — In tree | Is the package in the dependency tree at all? | ✓ They check this |
| L2 — Semver admits | Does the declared version range actually admit the compromised version? | ✗ Usually skipped |
| L3 — Symbol reachable | Walking the real import chain, would the malicious code actually execute? | ✗ Never done |

The result: what looks like hundreds of exposed packages collapses to the handful that genuinely need immediate action.

**Three-state honesty rule:** every package resolves to `REACHABLE`, `SAFE`, or `UNKNOWN`. Anything that can't be statically determined — minified code, dynamic imports, native bindings — is surfaced as `UNKNOWN` and never silently called safe.

---

## Demo

**Replay mode** — the real November 2018 event-stream supply chain attack, replayed from cached evidence with no network required. Validated against npm's published postmortem.

**Live scan** — type any npm package name. RIPPLE queries OSV.dev for real advisories, fetches live dependents, and streams results as the investigation runs.

![RIPPLE demo showing terminal and graph building in sync]

---

## Prerequisites

- Python 3.9 or higher
- pip
- A modern browser (Chrome, Firefox, Edge)
- Internet connection for Live Scan mode (Replay mode works offline)

---

## Setup

**1. Clone the repository**
```bash
git clone https://github.com/YOUR_USERNAME/ripple.git
cd ripple
```

**2. Install Python dependencies**
```bash
pip install -r requirements.txt
```

**3. Start the backend**
```bash
python server.py
```
The API will be available at `http://localhost:8000`.

**4. In a second terminal, serve the frontend**
```bash
python -m http.server 3000
```

**5. Open the app**

Go to `http://localhost:3000` in your browser.

---

## Usage

### Replay mode
Click **"Replay a real incident"** — the 2018 event-stream attack runs instantly from cached data with no network. Use this for demos or offline environments.

### Live scan
Click **"Scan any package"**, type an npm package name, and press Scan.

Good packages to try:
- `minimist` — real prototype pollution CVE, clear fix suggestion
- `lodash` — widely depended upon, interesting semver narrowing
- `chalk` — clean result, useful for showing the "no known vulnerabilities" path
- `debug` — transitive in almost everything, shows the funnel working at scale
- `event-stream` — rediscovers the 2018 incident live from OSV

The terminal narrates the investigation line by line as it runs. The graph builds in lockstep — each node appears the moment its result is computed, not at the end.

Click any node to see:
- **Why it's exposed** — plain-language explanation built from real chain data and OSV advisory text
- **How to fix it** — computed version bump, dependency override snippet, or structural fix if no patched version exists
- **Technical evidence** — the full L1 → L2 → L3 chain with source locations

---

## How it works

```
Browser
  │  EventSource('/api/scan/stream?package=NAME')
  ▼
FastAPI backend (server.py)
  │
  ├─ npm registry → resolve package, fetch dependents
  ├─ OSV.dev      → find real advisories and affected version ranges
  ├─ deps.dev     → dependency graph
  ├─ semver gate  → does each consumer's range admit the compromised version?
  ├─ tarball scan → download and walk the real import chain, hop by hop
  └─ stream events → log / node / edge / status / final
```

**The chain walk** is the core. For a chain like `nodemon → ps-tree → event-stream → flatmap-stream`, reachability is not checked by asking whether `nodemon` mentions `flatmap-stream` — it walks every hop and checks whether each `require` or `import` is unconditional. A conditional import breaks the chain; an unanalysable one becomes `UNKNOWN`.

---

## Project structure

```
ripple/
├── server.py              # FastAPI backend — SSE streaming endpoint
├── scan/
│   ├── registry.py        # npm registry and deps.dev client
│   ├── osv.py             # OSV.dev advisory queries
│   ├── semver_gate.py     # L2: version range evaluation
│   ├── tarball.py         # tarball fetch and extraction
│   ├── reachability.py    # L3: import chain walk
│   ├── explain.py         # plain-language exposure explanation
│   └── mitigate.py        # computed fix suggestions
├── data/
│   └── replay/            # cached event-stream 2018 evidence
├── index.html             # single-page frontend
├── app.js                 # Cytoscape graph + terminal + EventSource client
├── styles.css
└── requirements.txt
```

---

## API

### `GET /api/scan/stream?package=NAME&mode=real|simulate`

Server-Sent Events stream. Events:

| Event | Payload | When |
|-------|---------|------|
| `log` | `{ level, text }` | Each step as it runs |
| `node` | `{ id, label, version }` | Each dependent resolved |
| `edge` | `{ from, to, gate, verdict }` | Each relationship evaluated |
| `status` | `{ id, state, evidence }` | Each package's final verdict |
| `final` | `{ counts }` | Scan complete — funnel totals |

States: `reachable` · `safe` · `unknown` · `source`

### `GET /api/replay/event-stream-2018`

Returns the full cached funnel result for the 2018 incident. No network required.

---

## Validation

The event-stream replay is validated against npm's own published incident postmortem. For each consumer in the replay dataset, the computed chain walk result is compared against what the postmortem documents. The historical reference is cited inline in the UI footer.

For live scans, RIPPLE caps dependents at 25 by default (configurable in `server.py`) and states the cap explicitly in the terminal log. It does not silently truncate.

---

## Scope and honest limitations

**What RIPPLE can determine:**
- Whether a package is in the resolved dependency tree
- Whether a declared version range admits a compromised release
- Whether import chains are unconditional based on static analysis of real source files

**What RIPPLE cannot determine:**
- Whether a vulnerability in upstream code is exploitable in isolation (that is security research, not dependency analysis)
- Runtime behaviour — a conditional import that always evaluates true at runtime looks the same as one that evaluates false
- Anything inside minified, obfuscated, or native-binding files — these surface as `UNKNOWN`

**Ecosystem:** npm only in the current build. The L1 and L2 gates are ecosystem-agnostic (deps.dev and OSV.dev both cover PyPI, Maven, and others). L3 requires a per-language import scanner — Python `ast` would cover PyPI with modest additional work.

---

## Built with

- [FastAPI](https://fastapi.tiangolo.com/) — backend and SSE streaming
- [OSV.dev](https://osv.dev/) — open vulnerability database
- [deps.dev](https://deps.dev/) — dependency graph API
- [Cytoscape.js](https://js.cytoscape.org/) — graph rendering
- [npm registry](https://registry.npmjs.org/) — package metadata and tarballs

---

## Hackathon context

Built for Manipal Hackathon 2026 — Problem Statement: **Open Source Supply Chains: The Ripple Effect** (Industry, Innovation and Infrastructure track).

---

## License

MIT
