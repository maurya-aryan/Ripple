"""
build_data.py — RIPPLE data pipeline for the Nov 2018 event-stream/flatmap-stream incident.

Real incident facts (all sourced from public documentation):
  - event-stream 3.3.6 was published 2018-09-09 by attacker who took over the package
    It added flatmap-stream 0.1.1 as a DIRECT dependency.
  - flatmap-stream 0.1.1 contained an AES-256 encrypted payload targeting Copay wallet.
  - event-stream 3.3.6 was unpublished after the incident; no longer in npm registry.
  - The poisoned version was event-stream ^3.3.x range resolvers.
  - Source: https://blog.npmjs.org/post/180565383195/details-about-the-event-stream-incident

Dependency model:
  - flatmap-stream@0.1.1  ← malicious root
  - event-stream@3.3.6    ← added flatmap-stream 0.1.1 as direct dep (version removed from registry)
  - Consumers that declared event-stream at a range admitting 3.3.6 were poisoned.

L2 semver question:
  Does this consumer's declared event-stream range satisfy/include 3.3.6?
  (semver.satisfies(range, '3.3.6') in semver terms)

This script:
  1. Lists 6 real packages with their verified declared event-stream ranges from npm registry.
  2. Computes L2 using a correct semver satisfies() implementation (in pure Python).
  3. Downloads the real tarballs for each.
  4. Writes data/graph.json (L3 left as null; filled by reachability/scan.py).
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
# Supports ranges: ^, ~, >=, <=, >, <, =, X.Y.Z, X.Y.x, *
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
    Returns True/False. Conservative: unknown operators → None (treat as not admits).
    """
    target = parse_version(target_version)
    range_str = range_str.strip()

    # Handle || (OR) ranges
    if '||' in range_str:
        return any(semver_satisfies(r.strip(), target_version)
                   for r in range_str.split('||'))

    # Handle space-separated AND ranges like ">=1.0.0 <2.0.0"
    parts = range_str.split()
    if len(parts) > 1 and not range_str.startswith('^') and not range_str.startswith('~'):
        return all(semver_satisfies(p, target_version) for p in parts)

    # Caret: ^X.Y.Z  →  >=X.Y.Z <(X+1).0.0
    m = re.match(r'^\^(\d+)\.(\d+)\.(\d+)$', range_str)
    if m:
        lo = tuple(int(x) for x in m.groups())
        hi = (lo[0] + 1, 0, 0)
        return lo <= target < hi

    # Caret: ^X.Y  →  >=X.Y.0 <(X+1).0.0
    m = re.match(r'^\^(\d+)\.(\d+)$', range_str)
    if m:
        lo = (int(m.group(1)), int(m.group(2)), 0)
        hi = (lo[0] + 1, 0, 0)
        return lo <= target < hi

    # Tilde: ~X.Y.Z  →  >=X.Y.Z <X.(Y+1).0
    m = re.match(r'^~(\d+)\.(\d+)\.(\d+)$', range_str)
    if m:
        lo = tuple(int(x) for x in m.groups())
        hi = (lo[0], lo[1] + 1, 0)
        return lo <= target < hi

    # Tilde: ~X.Y  →  >=X.Y.0 <X.(Y+1).0
    m = re.match(r'^~(\d+)\.(\d+)$', range_str)
    if m:
        lo = (int(m.group(1)), int(m.group(2)), 0)
        hi = (lo[0], lo[1] + 1, 0)
        return lo <= target < hi

    # Exact X.Y.Z or =X.Y.Z
    m = re.match(r'^=?(\d+)\.(\d+)\.(\d+)$', range_str)
    if m:
        return target == tuple(int(x) for x in m.groups())

    # X.Y.x or X.Y.* wildcard
    m = re.match(r'^(\d+)\.(\d+)\.[xX*]$', range_str)
    if m:
        lo = (int(m.group(1)), int(m.group(2)), 0)
        hi = (lo[0], lo[1] + 1, 0)
        return lo <= target < hi

    # X.x or X.*
    m = re.match(r'^(\d+)\.[xX*]$', range_str)
    if m:
        lo = (int(m.group(1)), 0, 0)
        hi = (lo[0] + 1, 0, 0)
        return lo <= target < hi

    # >=, <=, >, <
    for op, cmp in [('>=', lambda a, b: a >= b), ('<=', lambda a, b: a <= b),
                    ('>', lambda a, b: a > b), ('<', lambda a, b: a < b)]:
        if range_str.startswith(op):
            ver = parse_version(range_str[len(op):].strip())
            return cmp(target, ver)

    # X (bare major only)
    m = re.match(r'^(\d+)$', range_str)
    if m:
        lo = (int(m.group(1)), 0, 0)
        hi = (lo[0] + 1, 0, 0)
        return lo <= target < hi

    # * or ''
    if range_str in ('*', ''):
        return True

    return None  # unknown


# ──────────────────────────────────────────────────────────────
# Real packages with their VERIFIED declared event-stream ranges
# fetched/confirmed from the npm registry.
#
# L2 target version: event-stream 3.3.6 (the poisoned release, 2018-09-09)
# Packages whose declared range satisfies 3.3.6 would have pulled in
# flatmap-stream 0.1.1 transitively.
#
# CONFIRMED via npm registry (all package.json URLs can be verified):
# ──────────────────────────────────────────────────────────────
POISONED_EVENT_STREAM_VERSION = "3.3.6"

# Consumer packages with their REAL declared event-stream ranges
# (verified by fetching https://registry.npmjs.org/<pkg>/<ver>)
CONSUMER_PACKAGES = [
    {
        # ps-tree@1.1.0 dependencies.event-stream = "~3.3.0"
        # Source: https://registry.npmjs.org/ps-tree/1.1.0
        "name": "ps-tree",
        "version": "1.1.0",
        "declared_range": "~3.3.0",
        "tarball_url": "https://registry.npmjs.org/ps-tree/-/ps-tree-1.1.0.tgz",
        "range_source": "https://registry.npmjs.org/ps-tree/1.1.0 → dependencies.event-stream",
    },
    {
        # nodemon@1.18.6 depends on ps-tree ^1.1.0 (transitive event-stream consumer)
        # nodemon itself does NOT directly declare event-stream, but resolves it transitively
        # via ps-tree. We include it to illustrate the transitive reach.
        "name": "nodemon",
        "version": "1.18.6",
        "declared_range": "TRANSITIVE via ps-tree ^1.1.0",
        "tarball_url": "https://registry.npmjs.org/nodemon/-/nodemon-1.18.6.tgz",
        "range_source": "https://registry.npmjs.org/nodemon/1.18.6 → no direct event-stream dep",
    },
    {
        # from@0.1.7: a dep of event-stream 3.3.5, no event-stream in its own deps
        # included to show packages that are in the stream ecosystem but NOT consumers
        "name": "from",
        "version": "0.1.7",
        "declared_range": "NONE",
        "tarball_url": "https://registry.npmjs.org/from/-/from-0.1.7.tgz",
        "range_source": "https://registry.npmjs.org/from/0.1.7 → no event-stream dep",
    },
    {
        # through@2.3.8: another dep of event-stream 3.3.5, in the dep graph but no direct event-stream range
        "name": "through",
        "version": "2.3.8",
        "declared_range": "NONE",
        "tarball_url": "https://registry.npmjs.org/through/-/through-2.3.8.tgz",
        "range_source": "https://registry.npmjs.org/through/2.3.8 → no event-stream dep",
    },
    {
        # split@1.0.1: dep of event-stream 3.3.5 (^1.0.1), uses through internally
        "name": "split",
        "version": "1.0.1",
        "declared_range": "NONE",
        "tarball_url": "https://registry.npmjs.org/split/-/split-1.0.1.tgz",
        "range_source": "https://registry.npmjs.org/split/1.0.1 → no event-stream dep",
    },
    {
        # stream-combiner@0.2.2: dep of event-stream 3.3.5 (^0.2.2)
        "name": "stream-combiner",
        "version": "0.2.2",
        "declared_range": "NONE",
        "tarball_url": "https://registry.npmjs.org/stream-combiner/-/stream-combiner-0.2.2.tgz",
        "range_source": "https://registry.npmjs.org/stream-combiner/0.2.2 → no event-stream dep",
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
        print(f"  Already have {filename} ({os.path.getsize(filepath)} bytes)")
        return filepath
    try:
        print(f"  Downloading {url}...")
        content = fetch_with_retry(url)
        with open(filepath, 'wb') as f:
            f.write(content)
        print(f"  ✓ {filename} ({len(content):,} bytes)")
        return filepath
    except Exception as e:
        print(f"  ✗ FAILED {filename}: {e} — logged in ASSUMPTIONS")
        return None


def verify_declared_range(name, version):
    """Fetch the real package.json from npm and extract the event-stream declared range."""
    try:
        url = f"https://registry.npmjs.org/{name}/{version}"
        data = json.loads(fetch_with_retry(url).decode())
        deps = data.get('dependencies', {})
        es_range = deps.get('event-stream')
        flat_range = deps.get('flatmap-stream')
        return es_range, flat_range
    except Exception as e:
        return None, None


def main():
    print("=" * 60)
    print("RIPPLE — event-stream 2018 incident data pipeline")
    print(f"L2 target: event-stream@{POISONED_EVENT_STREAM_VERSION} (poisoned)")
    print("=" * 60)

    graph_data = []
    assumptions = []

    for pkg in CONSUMER_PACKAGES:
        name = pkg["name"]
        version = pkg["version"]
        tarball_url = pkg["tarball_url"]

        print(f"\n[{name}@{version}]")

        # Verify declared range from npm registry
        real_es_range, real_flat_range = verify_declared_range(name, version)
        if real_es_range is not None:
            declared_range = real_es_range
            print(f"  ✓ Verified from npm: event-stream declared as {declared_range!r}")
        elif real_flat_range is not None:
            declared_range = f"flatmap-stream: {real_flat_range}"
            print(f"  ✓ Verified from npm: flatmap-stream declared as {real_flat_range!r}")
        elif pkg["declared_range"] in ("NONE", "TRANSITIVE via ps-tree ^1.1.0"):
            declared_range = pkg["declared_range"]
            print(f"  ℹ No direct event-stream dep: {declared_range}")
        else:
            declared_range = pkg["declared_range"]
            assumptions.append(f"{name}@{version}: npm fetch failed, using pre-researched range {declared_range!r}")
            print(f"  ⚠ Using pre-researched range: {declared_range!r}")

        # L1: in_tree — all packages in our dependency graph are in-tree
        in_tree = True

        # L2: semver_admits — does declared range satisfy poisoned event-stream 3.3.6?
        semver_result = semver_satisfies(declared_range, POISONED_EVENT_STREAM_VERSION)
        if declared_range in ("NONE", "TRANSITIVE via ps-tree ^1.1.0"):
            # Can't compute L2 for packages with no direct event-stream dep
            semver_admits = None
            l2_evidence = (f"L2: No direct event-stream dependency declared. "
                           f"L2 gate N/A ({declared_range})")
        elif semver_result is None:
            semver_admits = None
            l2_evidence = (f"L2: UNKNOWN — Could not parse range {declared_range!r} against "
                           f"event-stream {POISONED_EVENT_STREAM_VERSION}")
            assumptions.append(f"{name}: semver range {declared_range!r} could not be parsed")
        elif semver_result:
            semver_admits = True
            l2_evidence = (f"L2: range {declared_range!r} ADMITS event-stream@{POISONED_EVENT_STREAM_VERSION} "
                           f"(the poisoned build that pulled in flatmap-stream@0.1.1)")
        else:
            semver_admits = False
            l2_evidence = (f"L2: range {declared_range!r} REJECTS event-stream@{POISONED_EVENT_STREAM_VERSION} "
                           f"— package would NOT have resolved the poisoned build")

        print(f"  L2 semver_admits: {semver_admits}")

        # Download tarball
        filepath = download_tarball(name, version, tarball_url)
        if filepath is None:
            assumptions.append(f"{name}@{version}: tarball download failed")

        evidence = [
            f"L1: present in resolved event-stream dependency graph ({name}@{version})",
            l2_evidence,
        ]

        node = {
            "name": name,
            "version": version,
            "in_tree": in_tree,
            "declared_range": declared_range,
            "semver_admits": semver_admits,
            "symbol_reachable": None,
            "evidence": evidence,
        }
        graph_data.append(node)

    # Also add event-stream and flatmap-stream themselves as the root nodes
    print("\n[event-stream@3.3.6 — POISONED ROOT]")
    print("  Note: This version was removed from npm after the incident.")
    print("  Downloading 3.3.4 (last clean version) as reference tarball.")
    download_tarball("event-stream", "3.3.4",
                     "https://registry.npmjs.org/event-stream/-/event-stream-3.3.4.tgz")

    graph_data.insert(0, {
        "name": "event-stream",
        "version": "3.3.6",
        "in_tree": True,
        "declared_range": "flatmap-stream: 0.1.1",
        "semver_admits": True,
        "symbol_reachable": None,
        "evidence": [
            "L1: event-stream@3.3.6 was the poisoned release (published 2018-09-09, unpublished after incident)",
            "L2: This IS the poisoned version; it directly declared flatmap-stream@0.1.1 in its package.json",
            "Source: https://blog.npmjs.org/post/180565383195/details-about-the-event-stream-incident",
        ],
    })

    print("\n[flatmap-stream@0.1.1 — MALICIOUS PAYLOAD]")
    download_tarball("flatmap-stream", "0.0.1-security",
                     "https://registry.npmjs.org/flatmap-stream/-/flatmap-stream-0.0.1-security.tgz")

    graph_data.insert(1, {
        "name": "flatmap-stream",
        "version": "0.1.1",
        "in_tree": True,
        "declared_range": "0.1.1",
        "semver_admits": True,
        "symbol_reachable": None,
        "evidence": [
            "L1: flatmap-stream@0.1.1 was the malicious package added by event-stream@3.3.6",
            "L2: This IS the malicious package; version 0.1.1 contained AES-256 encrypted payload",
            "Source: https://blog.npmjs.org/post/180565383195/details-about-the-event-stream-incident",
        ],
    })

    with open(GRAPH_JSON_PATH, "w") as f:
        json.dump(graph_data, f, indent=2)

    print(f"\n{'='*60}")
    print(f"Wrote {len(graph_data)} packages to {GRAPH_JSON_PATH}")
    if assumptions:
        print("\nASSUMPTIONS LOG:")
        for a in assumptions:
            print(f"  ⚠ {a}")
    print("="*60)


if __name__ == "__main__":
    main()
