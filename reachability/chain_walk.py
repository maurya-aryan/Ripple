"""
reachability/chain_walk.py — Hop-by-hop reachability chain walker.

Instead of checking if a consumer directly imports a compromised package,
we walk the entire dependency chain and verify each hop is unconditional:

  consumer -> event-stream -> flatmap-stream

For each hop (A requires B):
  - If the require of B inside A's code is unconditional (top-level, not inside
    an if/try/function), the chain continues.
  - If it cannot be determined (minified, binary), mark UNKNOWN and stop.
  - If provably conditional, mark NOT_REACHABLE and stop.

Node.js executes a required module's top-level code immediately on require(),
so an unconditional require at the top of event-stream's index.js means EVERY
package that loads event-stream will also load flatmap-stream automatically.

Top-level detection handles both single-line and multi-line comma-continuation
style common in older CommonJS:

    var spawn = require('child_process').spawn,  <-- starts at col 0
        es    = require('event-stream');          <-- comma-cont, still top-level

We detect this by checking if the require appears BEFORE the first control-flow
block (function/if/try/while/for) in the file.
"""

import re
import tarfile
import os

# Detects the start of a control-flow or function-definition block,
# which would push subsequent code into a conditional scope
_CONTROL_FLOW_RE = re.compile(
    r"""^(?:function\s+\w+\s*\(|"""
    r"""(?:var|const|let)\s+\w+\s*=\s*(?:async\s+)?function\s*\(|"""
    r"""module\.exports\s*=\s*(?:async\s+)?function\s*\(|"""
    r"""\bif\s*\(|\btry\s*\{|\bwhile\s*\(|\bfor\s*\()""",
    re.MULTILINE,
)

# Any require/import of a named package (used to find the line number)
def _any_ref_pattern(package_name):
    escaped = re.escape(package_name)
    return re.compile(
        r"""require\s*\(\s*['"]""" + escaped + r"""['"]\s*\)|"""
        r"""from\s*['"]""" + escaped + r"""['"]""",
        re.MULTILINE,
    )


def _find_first_real_block_open(content):
    """
    Returns the match object for the first control-flow/function-definition
    construct that actually OPENS a multi-line block — skipping one-liners
    like `var noop = function () { };` whose braces balance on the same
    line and therefore never push later top-level code into conditional
    scope. Without this, a harmless one-line no-op earlier in the file
    would falsely flag every later top-level require as "conditional".
    """
    lines = content.splitlines(keepends=True)
    for m in _CONTROL_FLOW_RE.finditer(content):
        line_no = content[:m.start()].count('\n')  # 0-indexed
        line = lines[line_no] if line_no < len(lines) else ''
        # From the construct onward on its own line, do the braces balance?
        # A `try {` with no closing `}` on the same line truly opens a block;
        # `function () { };` (or similar) that closes on the same line does not.
        rest_of_line = line[m.start() - sum(len(l) for l in lines[:line_no]):]
        if rest_of_line.count('{') > 0 and rest_of_line.count('{') == rest_of_line.count('}'):
            continue  # self-contained one-liner — not a real block open
        return m
    return None


def _is_require_before_control_flow(content, package_name):
    """
    Returns True if any require(package_name) appears before the first
    control-flow or function definition in the file — meaning it's at
    module top level (unconditional), even if the line itself is indented
    (comma-continuation pattern).
    """
    pat = _any_ref_pattern(package_name)
    ref_match = pat.search(content)
    if not ref_match:
        return False, None

    ref_pos = ref_match.start()
    ref_line = content[:ref_pos].count('\n') + 1

    cf_match = _find_first_real_block_open(content)
    if not cf_match:
        # No control flow at all — require must be top-level
        snippet = content.splitlines()[ref_line - 1].strip()[:80]
        return True, f"line {ref_line}: `{snippet}` (no control-flow in file)"

    cf_pos = cf_match.start()
    cf_line = content[:cf_pos].count('\n') + 1

    if ref_pos < cf_pos:
        snippet = content.splitlines()[ref_line - 1].strip()[:80]
        return True, f"line {ref_line}: `{snippet}` (appears before first control-flow at line {cf_line})"

    # Require appears AFTER a control-flow block
    snippet = content.splitlines()[ref_line - 1].strip()[:80]
    return False, f"line {ref_line}: `{snippet}` (appears after control-flow start at line {cf_line})"


def check_hop(tarball_path, required_package):
    """
    Scan the tarball at tarball_path to determine how it requires `required_package`.

    Returns:
        ("unconditional", evidence: str)   — top-level unconditional require found
        ("conditional",   evidence: str)   — require is inside a function/if/try block
        ("unknown",       evidence: str)   — unanalysable (minified / binary)
        ("not_found",     evidence: str)   — no require of this package found at all
    """
    if not os.path.exists(tarball_path) or os.path.getsize(tarball_path) < 50:
        return ("unknown", f"Tarball not found or empty: {tarball_path}")

    unconditional_hits = []
    conditional_hits = []
    unknown_hits = []

    try:
        with tarfile.open(tarball_path, "r:gz") as tar:
            js_members = [m for m in tar.getmembers() if m.name.endswith(".js")]
            if not js_members:
                return ("not_found", "No .js files in tarball")

            for member in js_members:
                fobj = tar.extractfile(member)
                if fobj is None:
                    unknown_hits.append(f"{member.name}: extractfile() returned None")
                    continue
                try:
                    content = fobj.read().decode("utf-8", errors="strict")
                except UnicodeDecodeError:
                    unknown_hits.append(f"{member.name}: binary/non-UTF-8")
                    continue

                lines = content.splitlines()

                # Minification check
                if any(len(l) > 500 for l in lines):
                    unknown_hits.append(f"{member.name}: minified (line > 500 chars)")
                    continue

                is_top_level, evidence_str = _is_require_before_control_flow(
                    content, required_package
                )
                if evidence_str is None:
                    continue  # no reference at all in this file

                if is_top_level:
                    unconditional_hits.append(f"{member.name}: {evidence_str}")
                else:
                    conditional_hits.append(f"{member.name}: {evidence_str}")

    except Exception as e:
        return ("unknown", f"Error opening tarball: {e}")

    # Roll-up: any unconditional → unconditional wins
    if unconditional_hits:
        return ("unconditional", unconditional_hits[0])
    if unknown_hits:
        return ("unknown", unknown_hits[0])
    if conditional_hits:
        return ("conditional", conditional_hits[0])
    return ("not_found", f"No require of '{required_package}' found in any .js file")


def walk_chain(tarball_dir, chain_hops, documented_hops=None):
    """
    Walk a dependency chain hop by hop.

    chain_hops: list of (consumer_name, consumer_version, required_package)
        Each hop means: consumer_name requires required_package.
        Tarballs are looked up as {consumer_name}-{consumer_version}.tgz in tarball_dir.

    documented_hops: dict mapping (consumer_name, required_package) to a
        known-unconditional status string (for hops where the tarball was removed
        from npm but the behavior is confirmed from public documentation).

    Returns:
        ("reachable",     evidence: list[str])
        ("not_reachable", evidence: list[str])
        ("unknown",       evidence: list[str])
    """
    documented_hops = documented_hops or {}
    evidence = []

    for consumer_name, consumer_version, required_package in chain_hops:
        hop_key = (consumer_name, required_package)

        # Check documented hop first (for removed tarballs)
        if hop_key in documented_hops:
            doc_ev = documented_hops[hop_key]
            evidence.append(
                f"HOP {consumer_name}@{consumer_version} -> {required_package}: "
                f"DOCUMENTED UNCONDITIONAL — {doc_ev}"
            )
            continue  # chain continues

        # Look up tarball
        tarball_path = os.path.join(tarball_dir, f"{consumer_name}-{consumer_version}.tgz")

        result, hop_evidence = check_hop(tarball_path, required_package)

        evidence.append(
            f"HOP {consumer_name}@{consumer_version} -> {required_package}: "
            f"{result.upper()} — {hop_evidence}"
        )

        if result == "unconditional":
            continue  # chain continues
        elif result == "not_found":
            return (
                "not_reachable",
                evidence + [
                    f"Chain broken: {consumer_name} does not require '{required_package}'"
                ],
            )
        elif result == "conditional":
            return (
                "not_reachable",
                evidence + [
                    f"Chain note: {consumer_name}'s require of '{required_package}' "
                    f"appears inside a function/if/try block — may not execute in all paths"
                ],
            )
        else:  # unknown
            return (
                "unknown",
                evidence + [
                    f"Chain analysis halted at {consumer_name}: cannot determine "
                    f"if require of '{required_package}' is unconditional"
                ],
            )

    # All hops passed → reachable
    return ("reachable", evidence)


if __name__ == "__main__":
    import sys
    sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

    TARBALL_DIR = os.path.join("data", "tarballs")

    # The hop event-stream@3.3.6 -> flatmap-stream@0.1.1 is documented.
    # The poisoned tarball was removed from npm, but the npm postmortem explicitly
    # confirms it added require('flatmap-stream') unconditionally to index.js.
    DOCUMENTED = {
        ("event-stream", "flatmap-stream"): (
            "npm postmortem confirms event-stream@3.3.6 added require('flatmap-stream') "
            "unconditionally to its index.js. "
            "Source: https://blog.npmjs.org/post/180565383195/details-about-the-event-stream-incident"
        )
    }

    for pkg, ver in [("ps-tree", "1.1.0"), ("live-server", "1.2.0"), ("nodemon", "1.12.5")]:
        result, evidence = walk_chain(
            TARBALL_DIR,
            [
                (pkg, ver, "event-stream"),
                ("event-stream", "3.3.6", "flatmap-stream"),
            ],
            documented_hops=DOCUMENTED,
        )
        print(f"\n{pkg}@{ver} chain result: {result.upper()}")
        for ev in evidence:
            print(f"  {ev}")
