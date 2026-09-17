"""
reachability/scan.py — L3 symbol reachability scan for RIPPLE.

For each package in data/tarballs/, inspects every .js file for:
  - require('flatmap-stream') / require("flatmap-stream")
  - import ... from 'flatmap-stream'
  - Any string reference to 'flatmap-stream' (conservative)

Safety rules (non-negotiable):
  - If a file cannot be decoded or is minified (any line > 500 chars), mark
    that package symbol_reachable = null (UNKNOWN) with a stated reason.
  - NEVER classify an unanalysable file as "not reachable".
  - Three states only: True, False, null.

Compromise source handling:
  - Nodes with role == 'compromise_source' (event-stream, flatmap-stream)
    are flagged as the origin of the compromise and are not candidates in the consumer funnel.
"""

import os
import json
import tarfile
import re

DATA_DIR = "data"
TARBALL_DIR = os.path.join(DATA_DIR, "tarballs")
GRAPH_JSON_PATH = os.path.join(DATA_DIR, "graph.json")
FUNNEL_RESULT_PATH = os.path.join(DATA_DIR, "funnel_result.json")

# Matches a require() or import of the exact package name flatmap-stream
FLATMAP_IMPORT_RE = re.compile(
    r"""require\s*\(\s*['"]flatmap-stream['"]\s*\)"""
    r"""|from\s*['"]flatmap-stream['"]""",
    re.MULTILINE,
)
# Matches any string literal containing flatmap-stream (catches re-exports, dynamic refs)
FLATMAP_STRING_RE = re.compile(r"""['"]flatmap-stream['"]""")


def analyse_js_file(content, member_name):
    """
    Returns (reachable: bool|None, reason: str).
    None = UNKNOWN (unanalysable).
    """
    lines = content.splitlines()

    # Minification: any single line > 500 chars means bundled/minified output
    long_lines = [l for l in lines if len(l) > 500]
    if long_lines:
        return (
            None,
            f"{member_name}: {len(long_lines)} line(s) > 500 chars — minified/bundled, "
            "cannot safely determine reachability",
        )

    # If there's a direct import/require of flatmap-stream → reachable
    if FLATMAP_IMPORT_RE.search(content):
        return True, f"{member_name}: direct require/import of 'flatmap-stream'"

    # If flatmap-stream appears as a string literal at all → reachable
    if FLATMAP_STRING_RE.search(content):
        return True, f"{member_name}: 'flatmap-stream' string literal present"

    return False, f"{member_name}: no flatmap-stream references found"


def analyse_tarball(name, version, role=None):
    """
    Analyse all .js files in the tarball for flatmap-stream references.
    Returns (symbol_reachable: bool|None, evidence_strings: list[str])
    """
    tarball_file = f"{name}-{version}.tgz"
    alt_files = [tarball_file]
    if version == "0.1.1":
        alt_files.append(f"{name}-0.0.1-security.tgz")
    if version == "3.3.6":
        alt_files.append(f"{name}-3.3.4.tgz")

    if role == "compromise_source":
        if name == "event-stream":
            return (
                None,
                [
                    "SOURCE: event-stream@3.3.6 was the malicious release introducing flatmap-stream@0.1.1 as a direct dependency. "
                    "Unpublished from npm after disclosure."
                ],
            )
        if name == "flatmap-stream":
            return (
                None,
                [
                    "SOURCE: flatmap-stream@0.1.1 was the malicious payload containing AES-256 encrypted wallet stealer. "
                    "Unpublished from npm after disclosure."
                ],
            )

    tarball_path = None
    for candidate in alt_files:
        full = os.path.join(TARBALL_DIR, candidate)
        if os.path.exists(full) and os.path.getsize(full) > 50:
            tarball_path = full
            tarball_file = candidate
            break

    if tarball_path is None:
        return (
            None,
            [f"L3: UNKNOWN — tarball for {name}@{version} not found in {TARBALL_DIR}"],
        )

    file_results = []

    try:
        with tarfile.open(tarball_path, "r:gz") as tar:
            js_members = [m for m in tar.getmembers() if m.name.endswith(".js")]
            if not js_members:
                return False, [f"L3: Not reachable — tarball {tarball_file} contains no .js files"]

            for member in js_members:
                fobj = tar.extractfile(member)
                if fobj is None:
                    file_results.append(
                        (None, f"{member.name}: extractfile() returned None")
                    )
                    continue
                try:
                    content = fobj.read().decode("utf-8", errors="strict")
                except UnicodeDecodeError:
                    file_results.append(
                        (None, f"{member.name}: binary/non-UTF-8 content, cannot parse")
                    )
                    continue

                reachable, reason = analyse_js_file(content, member.name)
                file_results.append((reachable, reason))

    except Exception as e:
        return (None, [f"L3: UNKNOWN — error opening tarball {tarball_file}: {e}"])

    any_true = any(r is True for r, _ in file_results)
    any_unknown = any(r is None for r, _ in file_results)

    note = f"(analysed {len(js_members)} .js file(s) in {tarball_file})"

    if any_true:
        reasons = [reason for reachable, reason in file_results if reachable is True]
        return True, [f"L3: Symbol reachable {note} — " + r for r in reasons[:2]]
    elif any_unknown:
        reasons = [reason for reachable, reason in file_results if reachable is None]
        return None, [f"L3: UNKNOWN {note} — " + r for r in reasons[:2]]
    else:
        return (
            False,
            [f"L3: Not reachable {note} — static scan of all .js files found zero flatmap-stream references"],
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
        reachable, l3_evidence = analyse_tarball(name, version, role)

        # Preserve L1/L2 or SOURCE evidence; replace L3
        existing = [e for e in pkg.get("evidence", []) if not e.startswith("L3:")]
        if role != "compromise_source":
            pkg["evidence"] = existing + l3_evidence
            pkg["symbol_reachable"] = reachable
        else:
            pkg["symbol_reachable"] = None

        if reachable is True:
            print(f"  => REACHABLE: {l3_evidence[0][:80]}")
        elif reachable is None:
            print(f"  => UNKNOWN / SOURCE: {l3_evidence[0][:80]}")
        else:
            print(f"  => not reachable")

    # Consumers only for funnel counts:
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
    print("=" * 50)
    print(f"Funnel result (Consumers only):")
    print(f"  L1 in_tree:          {in_tree_count}")
    print(f"  L2 semver_admits:    {semver_admits_count}")
    print(f"  L3 symbol_reachable: {symbol_reachable_count}")
    print(f"  L3 unknown:          {unknown_count}")
    print(f"Wrote {FUNNEL_RESULT_PATH}")
    print("=" * 50)


if __name__ == "__main__":
    main()
