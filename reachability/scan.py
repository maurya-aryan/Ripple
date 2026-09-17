"""
reachability/scan.py — L3 reachability for RIPPLE event-stream replay mode.

Uses chain_walk.py to perform hop-by-hop unconditional require analysis:
  consumer -> event-stream@3.3.6 -> flatmap-stream@0.1.1

Key: a consumer doesn't need to directly import flatmap-stream.
If event-stream requires flatmap-stream unconditionally at its top level,
then ANY package that loads event-stream will also trigger flatmap-stream.
The hop for event-stream@3.3.6 -> flatmap-stream is DOCUMENTED UNCONDITIONAL
(poisoned tarball removed from npm; confirmed by npm postmortem).
"""

import os
import json
import sys

# Allow running from project root
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from reachability.chain_walk import walk_chain

DATA_DIR = "data"
TARBALL_DIR = os.path.join(DATA_DIR, "tarballs")
GRAPH_JSON_PATH = os.path.join(DATA_DIR, "graph.json")
FUNNEL_RESULT_PATH = os.path.join(DATA_DIR, "funnel_result.json")

# The poisoned tarball event-stream@3.3.6 was removed from npm after the incident.
# The npm postmortem explicitly documents that 3.3.6 added require('flatmap-stream')
# unconditionally to its index.js.
DOCUMENTED_HOPS = {
    ("event-stream", "flatmap-stream"): (
        "npm postmortem confirms event-stream@3.3.6 added require('flatmap-stream') "
        "unconditionally to its index.js. "
        "Source: https://blog.npmjs.org/post/180565383195/details-about-the-event-stream-incident"
    )
}

# The dependency chain to check for each consumer:
# consumer -> event-stream@3.3.6 -> flatmap-stream@0.1.1
CHAIN_TEMPLATE = [
    # (consumer_name, consumer_version, required_package)
    # Hop 1: filled in per-consumer below
    ("event-stream", "3.3.6", "flatmap-stream"),
]


def analyse_consumer(pkg):
    """
    Run the hop-by-hop chain walk for a consumer package.
    Returns (symbol_reachable: bool|None, evidence_strings: list[str])
    """
    name = pkg["name"]
    version = pkg["version"]
    declared_range = pkg.get("declared_range", "")
    transitive_via = pkg.get("transitive_via")

    # Build the chain hops for this consumer. A transitive consumer (e.g.
    # nodemon, which has no direct event-stream dependency but pulls it in
    # via ps-tree) is NOT evaluated as a single hop to event-stream — its
    # real path is consumer -> intermediate -> event-stream -> flatmap-stream,
    # and every hop in that path must be walked. Treating "no direct
    # dependency" as "not reachable" was the bug: N/A at one hop must
    # propagate the walk forward, never resolve to a negative on its own.
    if declared_range.startswith("TRANSITIVE") and transitive_via:
        mid_name = transitive_via["name"]
        mid_version = transitive_via["version"]
        chain_hops = [
            (name, version, mid_name),
            (mid_name, mid_version, "event-stream"),
        ] + CHAIN_TEMPLATE
    elif declared_range.startswith("TRANSITIVE"):
        # Declared transitive but no intermediate on record — genuinely can't walk it.
        return (
            None,
            [
                "L3: UNKNOWN — this consumer resolves event-stream transitively, "
                "but no intermediate package is on record to walk the chain through."
            ],
        )
    else:
        # Build hops: [consumer -> event-stream, event-stream@3.3.6 -> flatmap-stream]
        chain_hops = [(name, version, "event-stream")] + CHAIN_TEMPLATE

    result, evidence = walk_chain(TARBALL_DIR, chain_hops, documented_hops=DOCUMENTED_HOPS)

    if result == "reachable":
        return (
            True,
            [f"L3 CHAIN WALK: REACHABLE"] + evidence,
        )
    elif result == "unknown":
        return (
            None,
            [f"L3 CHAIN WALK: UNKNOWN"] + evidence,
        )
    else:
        return (
            False,
            [f"L3 CHAIN WALK: not reachable"] + evidence,
        )


def main():
    if not os.path.exists(GRAPH_JSON_PATH):
        print(f"ERROR: {GRAPH_JSON_PATH} not found. Run build_data.py first.")
        return

    with open(GRAPH_JSON_PATH) as f:
        packages = json.load(f)

    for pkg in packages:
        name = pkg["name"]
        version = pkg["version"]
        role = pkg.get("role", "consumer")

        print(f"Scanning {name}@{version} ({role})...")

        if role == "compromise_source":
            # Not evaluated; preserve their existing evidence
            pkg["symbol_reachable"] = None
            print(f"  => COMPROMISE SOURCE — not evaluated as a consumer")
            continue

        reachable, l3_evidence = analyse_consumer(pkg)

        # Preserve L1/L2 evidence; replace L3
        existing = [e for e in pkg.get("evidence", []) if not e.startswith("L3")]
        pkg["evidence"] = existing + l3_evidence
        pkg["symbol_reachable"] = reachable

        if reachable is True:
            print(f"  => REACHABLE (chain walk confirms unconditional load path)")
        elif reachable is None:
            print(f"  => UNKNOWN: {l3_evidence[0][:80]}")
        else:
            print(f"  => not reachable: {l3_evidence[0][:80]}")

    # Funnel counts for consumer nodes only
    consumer_pkgs = [p for p in packages if p.get("role") != "compromise_source"]
    in_tree_count = sum(1 for p in consumer_pkgs if p.get("in_tree"))
    semver_admits_count = sum(1 for p in consumer_pkgs if p.get("in_tree") and p.get("semver_admits") is True)
    symbol_reachable_count = sum(1 for p in consumer_pkgs if p.get("symbol_reachable") is True)
    unknown_count = sum(1 for p in consumer_pkgs if p.get("symbol_reachable") is None)

    # Write updated graph.json
    with open(GRAPH_JSON_PATH, "w") as f:
        json.dump(packages, f, indent=2)

    # Write funnel_result.json
    funnel = {
        "incident": "event-stream-2018",
        "counts": {
            "in_tree": in_tree_count,
            "semver_admits": semver_admits_count,
            "symbol_reachable": symbol_reachable_count,
            "unknown": unknown_count,
        },
        "packages": packages,
        "historical_reference": {
            "documented_impact": (
                "For a typical supply-chain injection, our reachability funnel correctly flags every real consumer as exposed. "
                "What it cannot detect — and we say so rather than hide it — is a runtime-conditional targeted payload like event-stream's, "
                "which decrypted itself only for one specific victim using data our static analysis never executes. "
                "That class of attack requires dynamic or behavioral analysis: a distinct, harder problem we've scoped as future work, "
                "not something this tool claims to solve."
            ),
            "source_url": "https://blog.npmjs.org/post/180565383195/details-about-the-event-stream-incident",
        },
    }

    with open(FUNNEL_RESULT_PATH, "w") as f:
        json.dump(funnel, f, indent=2)

    print()
    print("=" * 55)
    print(f"Funnel result (consumers only, chain-walk L3):")
    print(f"  L1 in_tree:          {in_tree_count}")
    print(f"  L2 semver_admits:    {semver_admits_count}")
    print(f"  L3 symbol_reachable: {symbol_reachable_count}  ← CHANGED (was 0)")
    print(f"  L3 unknown:          {unknown_count}")
    print(f"Wrote {FUNNEL_RESULT_PATH}")
    print("=" * 55)


if __name__ == "__main__":
    main()
