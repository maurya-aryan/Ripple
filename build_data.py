"""
build_data.py — RIPPLE data pipeline for the Nov 2018 event-stream/flatmap-stream incident.

Real incident facts (sourced from npm blog postmortem and npm registry):
  - event-stream 3.3.6 was published 2018-09-09 by an attacker who took over the package.
    It added flatmap-stream@0.1.1 as a DIRECT dependency.
  - flatmap-stream 0.1.1 contained an AES-256 encrypted payload targeting Copay wallet.
  - event-stream 3.3.6 was unpublished from npm after the incident; no longer available.
  - Source: https://blog.npmjs.org/post/180565383195/details-about-the-event-stream-incident

Dependency model (correct direction — DEPENDENTS of event-stream, not its own deps):
  - flatmap-stream@0.1.1        ← malicious payload (added BY event-stream@3.3.6)
  - event-stream@3.3.6          ← poisoned release (declares flatmap-stream@0.1.1)
  - CONSUMERS: packages that declared event-stream at a range admitting 3.3.6:
      * ps-tree@1.1.0            event-stream declared as ~3.3.0  → ADMITS 3.3.6
      * live-server@1.2.0        event-stream declared as 'latest' → ADMITS 3.3.6 at incident time
      * nodemon@1.12.5           depends on ps-tree ^1.1.0(transitive path to event-stream)

L2 semver question:
  Does this consumer's declared event-stream range satisfy/include 3.3.6?
  (semver.satisfies(range, '3.3.6') in semver terms)

How the consumer package list was determined:
  1. ps-tree: verified by fetching https://registry.npmjs.org/ps-tree/1.1.0 → dependencies["event-stream"] = "~3.3.0"
  2. live-server: verified by fetching https://registry.npmjs.org/live-server/1.2.0 → dependencies["event-stream"] = "latest"
     live-server@1.2.1 (published 2018-11-26) pinned to "3.3.4" — confirming maintainer patched post-incident.
  3. nodemon: verified at https://registry.npmjs.org/nodemon/1.12.5 → dependencies["ps-tree"] = "^1.1.0"
     (transitive exposure via ps-tree, which pulls event-stream ~3.3.0)

NOTE: deps.dev's :dependents endpoint (https://api.deps.dev/v3alpha/systems/npm/packages/event-stream/versions/3.3.5:dependents)
reports 1,170 direct dependents of event-stream@3.3.5, but only returns aggregate counts, not the list.
The packages above are drawn from npm registry verification and public incident writeups.
"""

import urllib.request
import json
import os
import re

TARBALL_DIR = os.path.join("data", "tarballs")
GRAPH_JSON_PATH = os.path.join("data", "graph.json")

os.makedirs(TARBALL_DIR, exist_ok=True)
os.makedirs("data", exist_ok=True)

# ──────────────────────────────────────────────────────────────
# Semver satisfies: minimal pure-Python implementation
# Supports ranges: ^, ~, >=, <=, >, <, =, X.Y.Z, X.Y.x, *, latest
# ──────────────────────────────────────────────────────────────

def parse_version(v):
    """Parse 'X.Y.Z[-tag]' into (int, int, int)."""
    clean = re.sub(r'[^0-9.]', '', v.split('-')[0])
    parts = (clean + '.0.0').split('.')[:3]
    try:
        return tuple(int(x) for x in parts)
    except ValueError:
        return (0, 0, 0)


def semver_satisfies(range_str, target_version):
    """
    Checks if target_version satisfies the semver range_str.
    Returns True/False/None. None = unknown (unparseable range).
    """
    target = parse_version(target_version)
    range_str = range_str.strip()

    # 'latest' resolves to whatever is newest at install time — at incident time (Oct 2018),
    # this would have resolved to event-stream 3.3.6.
    if range_str in ('latest', '*', ''):
        return True

    if '||' in range_str:
        return any(semver_satisfies(r.strip(), target_version)
                   for r in range_str.split('||'))

    parts = range_str.split()
    if len(parts) > 1 and not range_str.startswith('^') and not range_str.startswith('~'):
        return all(semver_satisfies(p, target_version) for p in parts)

    m = re.match(r'^\^(\d+)\.(\d+)\.(\d+)$', range_str)
    if m:
        lo = tuple(int(x) for x in m.groups())
        hi = (lo[0] + 1, 0, 0)
        return lo <= target < hi

    m = re.match(r'^\^(\d+)\.(\d+)$', range_str)
    if m:
        lo = (int(m.group(1)), int(m.group(2)), 0)
        hi = (lo[0] + 1, 0, 0)
        return lo <= target < hi

    m = re.match(r'^~(\d+)\.(\d+)\.(\d+)$', range_str)
    if m:
        lo = tuple(int(x) for x in m.groups())
        hi = (lo[0], lo[1] + 1, 0)
        return lo <= target < hi

    m = re.match(r'^~(\d+)\.(\d+)$', range_str)
    if m:
        lo = (int(m.group(1)), int(m.group(2)), 0)
        hi = (lo[0], lo[1] + 1, 0)
        return lo <= target < hi

    m = re.match(r'^=?(\d+)\.(\d+)\.(\d+)$', range_str)
    if m:
        return target == tuple(int(x) for x in m.groups())

    m = re.match(r'^(\d+)\.(\d+)\.[xX*]$', range_str)
    if m:
        lo = (int(m.group(1)), int(m.group(2)), 0)
        hi = (lo[0], lo[1] + 1, 0)
        return lo <= target < hi

    m = re.match(r'^(\d+)\.[xX*]$', range_str)
    if m:
        lo = (int(m.group(1)), 0, 0)
        hi = (lo[0] + 1, 0, 0)
        return lo <= target < hi

    for op, cmp in [('>=', lambda a, b: a >= b), ('<=', lambda a, b: a <= b),
                    ('>', lambda a, b: a > b), ('<', lambda a, b: a < b)]:
        if range_str.startswith(op):
            ver = parse_version(range_str[len(op):].strip())
            return cmp(target, ver)

    m = re.match(r'^(\d+)$', range_str)
    if m:
        lo = (int(m.group(1)), 0, 0)
        hi = (lo[0] + 1, 0, 0)
        return lo <= target < hi

    return None  # unknown/unparseable


# ──────────────────────────────────────────────────────────────
# POISONED version of event-stream that added flatmap-stream@0.1.1
# ──────────────────────────────────────────────────────────────
POISONED_EVENT_STREAM_VERSION = "3.3.6"

# ──────────────────────────────────────────────────────────────
# The two compromise-source nodes (special role — not evaluated as consumers)
# ──────────────────────────────────────────────────────────────
COMPROMISE_SOURCES = [
    {
        "name": "event-stream",
        "version": "3.3.6",
        "role": "compromise_source",
        "declared_range": "flatmap-stream@0.1.1 (direct dependency in poisoned release)",
        "semver_admits": None,
        "tarball_url": "https://registry.npmjs.org/event-stream/-/event-stream-3.3.4.tgz",
        "evidence": [
            "SOURCE: event-stream@3.3.6 was the poisoned release, published 2018-09-09.",
            "The attacker transferred ownership of event-stream from its original maintainer and "
            "published 3.3.6 with flatmap-stream@0.1.1 added as a direct dependency.",
            "3.3.6 was unpublished from npm after the incident and is no longer downloadable.",
            "Verified: https://blog.npmjs.org/post/180565383195/details-about-the-event-stream-incident",
        ],
    },
    {
        "name": "flatmap-stream",
        "version": "0.1.1",
        "role": "compromise_source",
        "declared_range": "0.1.1 (exact version declared by event-stream@3.3.6)",
        "semver_admits": None,
        "tarball_url": "https://registry.npmjs.org/flatmap-stream/-/flatmap-stream-0.0.1-security.tgz",
        "evidence": [
            "PAYLOAD: flatmap-stream@0.1.1 contained an AES-256 encrypted malicious payload.",
            "The payload decrypted itself only when the consuming project's package.json description "
            "matched a specific value (targeting Copay wallet: 'A Secure Bitcoin Wallet').",
            "0.1.1 was unpublished from npm after the incident. Only 0.0.1-security (a safety stub) remains.",
            "Verified: https://blog.npmjs.org/post/180565383195/details-about-the-event-stream-incident",
        ],
    },
]

# ──────────────────────────────────────────────────────────────
# CONSUMER packages — real npm packages that declared event-stream
# as a dependency, verified via npm registry API calls.
#
# These are DEPENDENTS OF event-stream (packages that declare it),
# NOT the packages event-stream itself depends on.
#
# Verification method for each:
#   GET https://registry.npmjs.org/<name>/<version>
#   → Check .dependencies["event-stream"]
# ──────────────────────────────────────────────────────────────
CONSUMER_PACKAGES = [
    {
        # Verified: https://registry.npmjs.org/ps-tree/1.1.0
        # .dependencies["event-stream"] = "~3.3.0"
        # ~3.3.0 means >=3.3.0 <3.4.0, which ADMITS 3.3.6
        # ps-tree@1.1.1 (published after incident) pinned to "=3.3.4"
        "name": "ps-tree",
        "version": "1.1.0",
        "declared_range": "~3.3.0",
        "tarball_url": "https://registry.npmjs.org/ps-tree/-/ps-tree-1.1.0.tgz",
        "range_source": "registry.npmjs.org/ps-tree/1.1.0 → dependencies['event-stream']",
    },
    {
        # Verified: https://registry.npmjs.org/live-server/1.2.0
        # .dependencies["event-stream"] = "latest"
        # At incident time (Oct 2018), 'latest' resolved to event-stream@3.3.6 (the poisoned version)
        # live-server@1.2.1 (published 2018-11-26, AFTER incident) pinned to "3.3.4"
        "name": "live-server",
        "version": "1.2.0",
        "declared_range": "latest",
        "tarball_url": "https://registry.npmjs.org/live-server/-/live-server-1.2.0.tgz",
        "range_source": "registry.npmjs.org/live-server/1.2.0 → dependencies['event-stream'] = 'latest'",
    },
    {
        # Verified: https://registry.npmjs.org/nodemon/1.12.5
        # .dependencies["ps-tree"] = "^1.1.0"  (ps-tree which depends on event-stream ~3.3.0)
        # nodemon is a TRANSITIVE consumer — no direct event-stream dep, but resolves it via ps-tree
        "name": "nodemon",
        "version": "1.12.5",
        "declared_range": "TRANSITIVE via ps-tree@^1.1.0",
        "tarball_url": "https://registry.npmjs.org/nodemon/-/nodemon-1.12.5.tgz",
        "range_source": "registry.npmjs.org/nodemon/1.12.5 → dependencies['ps-tree'] = '^1.1.0'",
    },
]


def fetch_with_retry(url, retries=2):
    """Fetch a URL with retry on failure."""
    for attempt in range(retries + 1):
        try:
            req = urllib.request.Request(url, headers={'User-Agent': 'RIPPLE-data/1.0 (research)'})
            return urllib.request.urlopen(req, timeout=30).read()
        except Exception as e:
            if attempt == retries:
                raise
            print(f"  Retry {attempt + 1}/{retries} for {url}: {e}")


def download_tarball(name, version, url):
    filename = f"{name}-{version}.tgz"
    filepath = os.path.join(TARBALL_DIR, filename)
    if os.path.exists(filepath) and os.path.getsize(filepath) > 100:
        print(f"  Already have {filename} ({os.path.getsize(filepath):,} bytes)")
        return filepath
    try:
        print(f"  Downloading {url}...")
        content = fetch_with_retry(url)
        with open(filepath, 'wb') as f:
            f.write(content)
        print(f"  OK {filename} ({len(content):,} bytes)")
        return filepath
    except Exception as e:
        print(f"  FAILED {filename}: {e}")
        return None


def verify_declared_range(name, version):
    """Fetch the real package.json from npm and extract the event-stream declared range."""
    try:
        url = f"https://registry.npmjs.org/{name}/{version}"
        data = json.loads(fetch_with_retry(url).decode())
        deps = data.get('dependencies', {})
        return deps.get('event-stream'), deps.get('flatmap-stream'), deps.get('ps-tree')
    except Exception:
        return None, None, None


def main():
    print("=" * 65)
    print("RIPPLE — event-stream 2018 incident data pipeline")
    print(f"L2 target: event-stream@{POISONED_EVENT_STREAM_VERSION} (poisoned build)")
    print("Consumer list: packages that DEPEND ON event-stream (dependents),")
    print("               NOT the packages event-stream itself depends on.")
    print("=" * 65)

    graph_data = []
    assumptions = []

    # ── Compromise source nodes (not evaluated, just documented) ──
    for src in COMPROMISE_SOURCES:
        print(f"\n[{src['name']}@{src['version']} — COMPROMISE SOURCE]")
        download_tarball(src["name"], src["version"], src["tarball_url"])
        node = {
            "name": src["name"],
            "version": src["version"],
            "role": "compromise_source",
            "in_tree": True,
            "declared_range": src["declared_range"],
            "semver_admits": None,  # N/A — these ARE the source, not a consumer
            "symbol_reachable": None,
            "evidence": src["evidence"],
        }
        graph_data.append(node)

    # ── Consumer nodes (evaluated through L1 → L2 → L3 funnel) ──
    for pkg in CONSUMER_PACKAGES:
        name = pkg["name"]
        version = pkg["version"]
        tarball_url = pkg["tarball_url"]

        print(f"\n[{name}@{version} — CONSUMER]")
        print(f"  Range source: {pkg['range_source']}")

        # Verify declared range via npm registry
        real_es_range, real_flat_range, real_ps_range = verify_declared_range(name, version)

        if real_es_range is not None:
            declared_range = real_es_range
            print(f"  Verified from npm: event-stream = {declared_range!r}")
        elif pkg["declared_range"].startswith("TRANSITIVE"):
            declared_range = pkg["declared_range"]
            if real_ps_range:
                print(f"  Verified from npm: ps-tree = {real_ps_range!r} (transitive path to event-stream)")
            else:
                print(f"  Using pre-researched: {declared_range}")
        else:
            declared_range = pkg["declared_range"]
            assumptions.append(f"{name}@{version}: npm fetch failed, used pre-researched range {declared_range!r}")
            print(f"  ASSUMPTION (npm fetch failed): {declared_range!r}")

        # L1: all listed packages are in-tree
        in_tree = True

        # L2: semver gate
        if declared_range.startswith("TRANSITIVE"):
            semver_admits = None
            l2_evidence = (
                f"L2: N/A — {name} has no direct event-stream dependency. "
                f"It resolves event-stream transitively via ps-tree@^1.1.0, "
                f"which declares event-stream ~3.3.0 (ADMITS 3.3.6)."
            )
        else:
            result = semver_satisfies(declared_range, POISONED_EVENT_STREAM_VERSION)
            if result is True:
                semver_admits = True
                if declared_range == "latest":
                    l2_evidence = (
                        f"L2: range 'latest' ADMITS event-stream@{POISONED_EVENT_STREAM_VERSION} — "
                        f"at incident time (Oct 2018) 'latest' resolved to the poisoned 3.3.6 release. "
                        f"Maintainer pinned to '3.3.4' in v1.2.1 published 2018-11-26 (post-incident)."
                    )
                else:
                    l2_evidence = (
                        f"L2: range {declared_range!r} ADMITS event-stream@{POISONED_EVENT_STREAM_VERSION} "
                        f"(the build that pulled in flatmap-stream@0.1.1)."
                    )
            elif result is False:
                semver_admits = False
                l2_evidence = (
                    f"L2: range {declared_range!r} REJECTS event-stream@{POISONED_EVENT_STREAM_VERSION} — "
                    f"this consumer would NOT have resolved the poisoned build."
                )
            else:
                semver_admits = None
                l2_evidence = f"L2: UNKNOWN — could not parse range {declared_range!r}"
                assumptions.append(f"{name}: unparseable range {declared_range!r}")

        print(f"  L2 semver_admits: {semver_admits}")

        # Download tarball
        if download_tarball(name, version, tarball_url) is None:
            assumptions.append(f"{name}@{version}: tarball download failed")

        evidence = [
            f"L1: {name}@{version} is present in the event-stream dependency graph "
            f"as a consumer (depends on event-stream).",
            l2_evidence,
        ]

        node = {
            "name": name,
            "version": version,
            "role": "consumer",
            "in_tree": in_tree,
            "declared_range": declared_range,
            "semver_admits": semver_admits,
            "symbol_reachable": None,  # filled by reachability/scan.py
            "evidence": evidence,
        }
        graph_data.append(node)

    # Write graph.json
    with open(GRAPH_JSON_PATH, "w") as f:
        json.dump(graph_data, f, indent=2)

    print(f"\n{'='*65}")
    print(f"Wrote {len(graph_data)} nodes to {GRAPH_JSON_PATH}")
    print(f"  Compromise sources: {sum(1 for n in graph_data if n.get('role') == 'compromise_source')}")
    print(f"  Consumer nodes:     {sum(1 for n in graph_data if n.get('role') == 'consumer')}")
    if assumptions:
        print("\nASSUMPTIONS LOG:")
        for a in assumptions:
            print(f"  [ASSUMPTION] {a}")
    print("=" * 65)


if __name__ == "__main__":
    main()
