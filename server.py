"""
server.py — RIPPLE FastAPI backend.

Serves:
  GET /                              → index.html (static)
  GET /api/replay/event-stream-2018  → static funnel_result.json (no network — guaranteed demo path)
  GET /api/scan/stream?package=NAME  → Server-Sent Events live scan (real npm/OSV.dev/ecosyste.ms data)

Run with:
  uvicorn server:app --port 8000 --reload

── Data sources for live scan ──────────────────────────────────────────────
  registry.npmjs.org   resolve packages, read manifests (dependencies + dist.tarball)
  api.osv.dev           real vulnerability advisories + affected version ranges
  packages.ecosyste.ms  the *list* of real dependent packages

Why ecosyste.ms and not deps.dev for the dependents list: deps.dev's
GetDependents (`:dependents`) endpoint only returns aggregate counts
(dependentCount / directDependentCount / indirectDependentCount) — confirmed
against the published API reference at https://docs.deps.dev/api/v3alpha/ —
it does not return the package list itself. We still call it for a
cross-referenced total, but the actual capped list of real dependents (used
to drive L1/L2/L3) comes from ecosyste.ms's dependent_packages endpoint,
which does return real package names. Sorting by `downloads` is required:
without a sort param, ecosyste.ms's query times out for very popular
packages (verified against chalk/debug/express during development).
"""

import asyncio
import json
import re
import urllib.parse
from pathlib import Path
from typing import AsyncGenerator, Optional

import httpx
from fastapi import FastAPI, Query
from fastapi.responses import Response, StreamingResponse
from fastapi.staticfiles import StaticFiles

from reachability.chain_walk import check_hop

# ──────────────────────────────────────────────────────────────
app = FastAPI(title="RIPPLE API")

BASE_DIR = Path(__file__).parent
DATA_DIR = BASE_DIR / "data"
TARBALL_DIR = DATA_DIR / "tarballs"
TARBALL_DIR.mkdir(parents=True, exist_ok=True)

NPM_REGISTRY = "https://registry.npmjs.org"
OSV_URL = "https://api.osv.dev/v1/query"
DEPS_DEV = "https://api.deps.dev/v3alpha"
ECOSYSTEMS = "https://packages.ecosyste.ms/api/v1/registries/npmjs.org/packages"

DEFAULT_CAP = 25
MAX_CAP = 50


# ──────────────────────────────────────────────────────────────
# semver: minimal pure-Python range matcher.
# Supports: ^, ~, exact, X.Y.x, comparators (>=,<=,>,<,=), space-separated
# AND ranges (e.g. ">=1.0.0 <1.2.6", the shape OSV.dev ranges normalize to),
# and "||" OR ranges. Returns True/False, or None when the range can't be
# parsed at all — that None must surface as UNKNOWN, never as a silent False.
# ──────────────────────────────────────────────────────────────

def _parse_version(v: str):
    clean = re.sub(r"[^0-9.]", "", v.split("-")[0])
    parts = (clean + ".0.0").split(".")[:3]
    try:
        return tuple(int(x) for x in parts)
    except ValueError:
        return None


def semver_satisfies(range_str: str, target_version: str) -> Optional[bool]:
    target = _parse_version(target_version)
    if target is None:
        return None
    range_str = (range_str or "").strip()
    if range_str in ("latest", "*", "", "x"):
        return True
    # Non-semver dependency specs (git urls, workspace refs, file paths, tags)
    if re.search(r"(git\+|github:|file:|workspace:|http:|https:|^[a-zA-Z][\w-]*$)", range_str) and not re.match(r"^[\^~=]?\d", range_str):
        return None
    if "||" in range_str:
        results = [semver_satisfies(r.strip(), target_version) for r in range_str.split("||")]
        if any(r is True for r in results):
            return True
        if all(r is False for r in results):
            return False
        return None

    parts = range_str.split()
    if len(parts) > 1 and not range_str.startswith("^") and not range_str.startswith("~"):
        results = [semver_satisfies(p, target_version) for p in parts]
        if any(r is None for r in results):
            return None
        return all(results)

    m = re.match(r"^\^(\d+)\.(\d+)\.(\d+)", range_str)
    if m:
        lo = tuple(int(x) for x in m.groups())
        hi = (lo[0] + 1, 0, 0) if lo[0] > 0 else ((0, lo[1] + 1, 0) if lo[1] > 0 else (0, 0, lo[2] + 1))
        return lo <= target < hi
    m = re.match(r"^\^(\d+)\.(\d+)$", range_str)
    if m:
        lo = (int(m.group(1)), int(m.group(2)), 0)
        hi = (lo[0] + 1, 0, 0) if lo[0] > 0 else (0, lo[1] + 1, 0)
        return lo <= target < hi
    m = re.match(r"^~(\d+)\.(\d+)\.(\d+)", range_str)
    if m:
        lo = tuple(int(x) for x in m.groups())
        hi = (lo[0], lo[1] + 1, 0)
        return lo <= target < hi
    m = re.match(r"^~(\d+)\.(\d+)$", range_str)
    if m:
        lo = (int(m.group(1)), int(m.group(2)), 0)
        hi = (lo[0], lo[1] + 1, 0)
        return lo <= target < hi
    m = re.match(r"^=?(\d+)\.(\d+)\.(\d+)$", range_str)
    if m:
        return target == tuple(int(x) for x in m.groups())
    m = re.match(r"^(\d+)\.(\d+)\.[xX*]$", range_str)
    if m:
        lo = (int(m.group(1)), int(m.group(2)), 0)
        hi = (lo[0], lo[1] + 1, 0)
        return lo <= target < hi
    m = re.match(r"^(\d+)\.[xX*]$", range_str)
    if m:
        lo = (int(m.group(1)), 0, 0)
        hi = (lo[0] + 1, 0, 0)
        return lo <= target < hi
    for op, cmp in [(">=", lambda a, b: a >= b), ("<=", lambda a, b: a <= b),
                    (">", lambda a, b: a > b), ("<", lambda a, b: a < b)]:
        if range_str.startswith(op):
            ver = _parse_version(range_str[len(op):].strip())
            if ver is None:
                return None
            return cmp(target, ver)
    m = re.match(r"^(\d+)$", range_str)
    if m:
        lo = (int(m.group(1)), 0, 0)
        hi = (lo[0] + 1, 0, 0)
        return lo <= target < hi
    return None  # unparseable → UNKNOWN, not False


def npm_encode(name: str) -> str:
    return urllib.parse.quote(name, safe="@")


class NotFoundError(Exception):
    pass


async def fetch_json(client: httpx.AsyncClient, method: str, url: str, retries: int = 2, **kwargs):
    """GET/POST with 429/5xx backoff. Raises on final failure."""
    last_exc = None
    for attempt in range(retries + 1):
        try:
            resp = await client.request(method, url, **kwargs)
            if resp.status_code == 404:
                raise NotFoundError(url)
            if resp.status_code == 429 or resp.status_code >= 500:
                if attempt < retries:
                    await asyncio.sleep(0.6 * (attempt + 1))
                    continue
                resp.raise_for_status()
            resp.raise_for_status()
            return resp.json()
        except NotFoundError:
            raise
        except httpx.HTTPStatusError:
            raise
        except Exception as e:
            last_exc = e
            if attempt < retries:
                await asyncio.sleep(0.5 * (attempt + 1))
                continue
            raise last_exc


# ──────────────────────────────────────────────────────────────
# SSE helpers
# ──────────────────────────────────────────────────────────────

def sse_event(event_type: str, data: dict) -> str:
    payload = json.dumps(data, ensure_ascii=False)
    return f"event: {event_type}\ndata: {payload}\n\n"


def log_event(text: str, level: str = "info") -> str:
    return sse_event("log", {"level": level, "text": text})


def node_event(pkg_id: str, label: str, version: str, role: str = "consumer") -> str:
    return sse_event("node", {"id": pkg_id, "label": label, "version": version, "role": role})


def edge_event(source: str, target: str, gate: str, verdict: str) -> str:
    return sse_event("edge", {"from": source, "to": target, "gate": gate, "verdict": verdict})


def status_event(pkg_id: str, state: str, evidence: list) -> str:
    return sse_event("status", {"id": pkg_id, "state": state, "evidence": evidence})


# ──────────────────────────────────────────────────────────────
# API: Replay Mode — reads a static file only, no network. Guaranteed to
# work with the network disconnected.
# ──────────────────────────────────────────────────────────────

@app.get("/api/replay/event-stream-2018")
def replay_data():
    path = DATA_DIR / "funnel_result.json"
    if not path.exists():
        return Response(
            content=json.dumps({"error": "funnel_result.json not found. Run build_data.py and reachability/scan.py first."}),
            media_type="application/json",
            status_code=404,
        )
    return Response(content=path.read_text(encoding="utf-8"), media_type="application/json")


# ──────────────────────────────────────────────────────────────
# API: Live Scan SSE
# ──────────────────────────────────────────────────────────────

def pick_compromised_version(versions: dict, vulns: list):
    """
    versions: {version_str: {...npm version metadata...}}
    vulns: list of {"id", "summary", "range": "combined AND range string"}

    Returns (compromised_version: str|None, matched_vuln_ids: list[str]).
    Picks the highest currently-published version that falls inside any
    advisory's affected range — the most recent vulnerable release still
    resolvable today. If no currently-published version matches (all
    vulnerable releases have since been unpublished/deprecated away),
    returns (None, []) — callers must treat that as UNKNOWN, not "safe".
    """
    parsed = []
    for v in versions.keys():
        t = _parse_version(v)
        if t is not None:
            parsed.append((t, v))
    parsed.sort(reverse=True)

    for _, v in parsed:
        matched = [vv["id"] for vv in vulns if semver_satisfies(vv["range"], v) is True]
        if matched:
            return v, matched
    return None, []


def normalize_osv_vulns(osv_data: dict, package_name: str) -> list:
    """
    OSV advisories are often multi-package (e.g. a lodash advisory also lists
    lodash-es, lodash.trim, ... as separately affected packages within the
    same record). We must only use the `affected` blocks whose package name
    exactly matches the package being scanned — mixing another package's
    range in as an OR branch would silently widen (or narrow) what "admits"
    means for this scan.
    """
    out = []
    for v in osv_data.get("vulns", []):
        vid = v.get("id", "?")
        summary = v.get("summary") or (v.get("details") or "")[:120] or "no summary"
        parts = []
        for aff in v.get("affected", []):
            aff_pkg = aff.get("package", {})
            if aff_pkg.get("ecosystem") != "npm" or aff_pkg.get("name") != package_name:
                continue
            for r in aff.get("ranges", []):
                if r.get("type") != "SEMVER":
                    continue
                comparators = []
                for evt in r.get("events", []):
                    if "introduced" in evt and evt["introduced"] not in ("0", ""):
                        comparators.append(f">={evt['introduced']}")
                    if "fixed" in evt:
                        comparators.append(f"<{evt['fixed']}")
                    if "last_affected" in evt:
                        comparators.append(f"<={evt['last_affected']}")
                if comparators:
                    parts.append(" ".join(comparators))
                else:
                    parts.append("*")  # no bound info at all — genuinely still unfixed
            # Malicious-package advisories (OSV "MAL-*" records, e.g. npm account
            # takeovers) often list exact poisoned versions instead of a range.
            for exact_ver in aff.get("versions", []):
                parts.append(f"={exact_ver}")
        if not parts:
            continue  # this advisory didn't actually name this package
        range_str = " || ".join(parts)
        out.append({"id": vid, "summary": summary, "range": range_str})
    return out


async def get_dependents(client: httpx.AsyncClient, name: str, latest_ver: str, cap: int):
    """
    Returns (total_count, capped_list[{name, version}], source_note, deps_dev_count).
    Never raises — a failure here degrades to an empty list with an honest
    warning rather than crashing the whole scan.
    """
    enc = npm_encode(name)
    total = None
    try:
        pkg_info = await fetch_json(client, "GET", f"{ECOSYSTEMS}/{enc}", retries=1)
        total = pkg_info.get("dependent_packages_count")
    except Exception:
        pass

    deps_dev_count = None
    try:
        dev_resp = await fetch_json(
            client, "GET",
            f"{DEPS_DEV}/systems/npm/packages/{enc}/versions/{npm_encode(latest_ver)}:dependents",
            retries=0,
        )
        deps_dev_count = dev_resp.get("directDependentCount")
    except Exception:
        pass

    try:
        data = await fetch_json(
            client, "GET", f"{ECOSYSTEMS}/{enc}/dependent_packages",
            params={"per_page": cap, "sort": "downloads"},
            retries=2, timeout=15.0,
        )
        deduped = []
        seen = set()
        for p in data:
            pname = p.get("name")
            pver = p.get("latest_release_number")
            if pname and pver and pname not in seen and pname != name:
                seen.add(pname)
                # This consumer's OWN dependent count — how many other packages
                # sit downstream of it. Used to rank mitigation priority: a
                # reachable consumer with a large downstream reach of its own
                # is a bigger lever to patch first than one with none.
                deduped.append({"name": pname, "version": pver, "downstream_reach": p.get("dependent_packages_count") or 0})
        if total is None:
            total = len(deduped)
        return total or 0, deduped[:cap], "ecosyste.ms dependent_packages (sorted by downloads)", deps_dev_count
    except Exception as e:
        return (total or 0), [], f"dependents lookup failed: {e}", deps_dev_count


async def live_scan_generator(package_name: str, mode: str, cap: int) -> AsyncGenerator[str, None]:
    async with httpx.AsyncClient(timeout=20.0, follow_redirects=True) as client:
        enc_name = npm_encode(package_name)

        # ── Step 1: Resolve on npm registry ─────────────────────
        yield log_event(f"Resolving '{package_name}' on the npm registry…")
        try:
            pkg_data = await fetch_json(client, "GET", f"{NPM_REGISTRY}/{enc_name}")
        except NotFoundError:
            yield log_event(f"'{package_name}' does not exist on the npm registry. Check the spelling and try again.", "warn")
            yield sse_event("final", {"error": "not_found", "package": package_name})
            return
        except Exception as e:
            yield log_event(f"Could not reach the npm registry: {e}", "warn")
            yield sse_event("final", {"error": str(e), "package": package_name})
            return

        latest_ver = pkg_data.get("dist-tags", {}).get("latest")
        versions = pkg_data.get("versions", {})
        if not latest_ver or latest_ver not in versions:
            yield log_event(f"'{package_name}' has no resolvable 'latest' version on npm.", "warn")
            yield sse_event("final", {"error": "no_latest_version", "package": package_name})
            return
        description = pkg_data.get("description", "")
        yield log_event(f"Found {package_name}@{latest_ver} — {description[:90]}", "ok")
        yield node_event(package_name, f"{package_name}\nv{latest_ver}", latest_ver, role="target")

        # ── Step 2: OSV.dev vulnerability lookup ────────────────
        yield log_event(f"Querying OSV.dev for known advisories against '{package_name}'…")
        vulns = []
        try:
            osv_data = await fetch_json(
                client, "POST", OSV_URL,
                json={"package": {"name": package_name, "ecosystem": "npm"}},
                retries=1,
            )
            vulns = normalize_osv_vulns(osv_data, package_name)
        except Exception as e:
            yield log_event(f"OSV.dev query failed: {e}. Continuing without advisory data.", "warn")

        simulated = False
        compromised_version = None
        matched_vuln_ids = []

        if vulns:
            for v in vulns:
                yield log_event(f"  {v['id']}: {v['summary'][:100]} (affected: {v['range']})", "warn")
            compromised_version, matched_vuln_ids = pick_compromised_version(versions, vulns)

        if mode == "simulate":
            simulated = True
            compromised_version = latest_ver
            yield log_event(
                f"SIMULATED COMPROMISE — treating {package_name}@{latest_ver} as hypothetically compromised. "
                f"This is not a real advisory; results below are a hypothetical blast-radius estimate.",
                "risk",
            )
        elif not vulns:
            yield log_event(f"No known vulnerabilities for '{package_name}' in OSV.dev.", "ok")
            yield sse_event("final", {
                "no_advisories": True,
                "package": package_name,
                "version": latest_ver,
                "can_simulate": True,
            })
            return
        elif compromised_version is None:
            yield log_event(
                f"Found {len(vulns)} advisory/advisories, but every affected version has since been "
                f"unpublished — no currently-installable version to test consumers' ranges against. "
                f"Marking dependent semver checks UNKNOWN rather than guessing.",
                "warn",
            )
        else:
            yield log_event(
                f"Using {package_name}@{compromised_version} as the compromised version "
                f"(matches {', '.join(matched_vuln_ids)}).",
                "risk",
            )

        yield status_event(
            package_name, "source",
            ([f"SIMULATED: {package_name}@{latest_ver} treated as a hypothetical compromise for this scan."]
             if simulated else
             [f"ADVISORY {v['id']}: {v['summary']} (affected: {v['range']})" for v in vulns]),
        )

        # ── Step 3: Find dependents ──────────────────────────────
        yield log_event(f"Fetching dependents of '{package_name}'…")
        total, dependents, source_note, deps_dev_count = await get_dependents(client, package_name, latest_ver, cap)
        if deps_dev_count is not None:
            yield log_event(
                f"deps.dev reports {deps_dev_count:,} direct dependents for {package_name}@{latest_ver} "
                f"(count only — deps.dev's API does not expose the dependent package list itself).",
                "info",
            )
        if total > len(dependents):
            yield log_event(f"Found {total:,} dependents — analysing {len(dependents)} (source: {source_note}).", "warn")
        elif dependents:
            yield log_event(f"Found {len(dependents)} dependents — analysing all of them (source: {source_note}).", "ok")
        else:
            yield log_event(f"No dependents could be resolved ({source_note}).", "warn")

        in_tree = 0
        semver_admits_count = 0
        symbol_reachable_count = 0
        unknown_count = 0
        all_packages = [{
            "name": package_name, "version": latest_ver, "role": "source",
            "in_tree": True, "declared_range": None, "semver_admits": None,
            "symbol_reachable": None, "simulated": simulated,
            "evidence": [f"ADVISORY {v['id']}: {v['summary']}" for v in vulns] or ["No advisory — simulated run." if simulated else ""],
        }]

        # ── Step 4/5: L1 → L2 → L3 per dependent ────────────────
        for dep in dependents:
            dep_name, dep_ver = dep["name"], dep["version"]
            dep_reach = dep.get("downstream_reach", 0)
            dep_id = dep_name
            yield node_event(dep_id, f"{dep_name}\nv{dep_ver}", dep_ver, role="consumer")
            await asyncio.sleep(0.04)

            evidence = []
            # L1: fetch this dependent's manifest at its current published version
            try:
                manifest = await fetch_json(client, "GET", f"{NPM_REGISTRY}/{npm_encode(dep_name)}/{dep_ver}", retries=1)
            except Exception as e:
                evidence.append(f"L1: UNKNOWN — could not fetch {dep_name}@{dep_ver}'s manifest ({e}).")
                unknown_count += 1
                yield edge_event(dep_id, package_name, "L1", "unknown")
                yield log_event(f"  [{dep_name}] manifest fetch failed — UNKNOWN", "warn")
                yield status_event(dep_id, "unknown", evidence)
                all_packages.append({"name": dep_name, "version": dep_ver, "role": "consumer",
                                      "in_tree": None, "declared_range": None, "semver_admits": None,
                                      "symbol_reachable": None, "evidence": evidence})
                continue

            declared_range = None
            for dep_field in ("dependencies", "peerDependencies", "optionalDependencies"):
                declared_range = (manifest.get(dep_field) or {}).get(package_name)
                if declared_range:
                    break

            if not declared_range:
                evidence.append(
                    f"L1: NOT IN TREE — {dep_name}@{dep_ver} (its current published version) does not declare "
                    f"'{package_name}' as a dependency. It may have upgraded away from it since being indexed."
                )
                yield edge_event(dep_id, package_name, "L1", "not_declared")
                yield log_event(f"  [{dep_name}] no longer depends on {package_name} — filtered out", "info")
                yield status_event(dep_id, "safe", evidence)
                all_packages.append({"name": dep_name, "version": dep_ver, "role": "consumer",
                                      "in_tree": False, "declared_range": None, "semver_admits": None,
                                      "symbol_reachable": None, "evidence": evidence})
                continue

            in_tree += 1
            evidence.append(f"L1: IN TREE — {dep_name}@{dep_ver} declares '{package_name}': \"{declared_range}\".")
            yield edge_event(dep_id, package_name, "L1", "in_tree")

            # L2: semver gate
            if compromised_version is None:
                admits = None
                evidence.append("L2: UNKNOWN — no concrete compromised version to compare against (see log).")
                yield edge_event(dep_id, package_name, "L2", "unknown")
                yield log_event(f"  [{dep_name}] L2 UNKNOWN (no compromised version resolved)", "warn")
                unknown_count += 1
                yield status_event(dep_id, "unknown", evidence)
                all_packages.append({"name": dep_name, "version": dep_ver, "role": "consumer",
                                      "in_tree": True, "declared_range": declared_range, "semver_admits": None,
                                      "symbol_reachable": None, "evidence": evidence})
                continue

            admits = semver_satisfies(declared_range, compromised_version)
            if admits is True:
                semver_admits_count += 1
                evidence.append(f"L2: ADMITS — range \"{declared_range}\" allows {package_name}@{compromised_version}.")
                yield edge_event(dep_id, package_name, "L2", "admits")
                yield log_event(f"  [{dep_name}] range \"{declared_range}\" ADMITS {compromised_version}", "risk")
            elif admits is False:
                evidence.append(f"L2: REJECTS — range \"{declared_range}\" excludes {package_name}@{compromised_version}. Never exposed.")
                yield edge_event(dep_id, package_name, "L2", "rejects")
                yield log_event(f"  [{dep_name}] range \"{declared_range}\" rejects {compromised_version} — filtered out", "ok")
                yield status_event(dep_id, "safe", evidence)
                all_packages.append({"name": dep_name, "version": dep_ver, "role": "consumer",
                                      "in_tree": True, "declared_range": declared_range, "semver_admits": False,
                                      "symbol_reachable": None, "evidence": evidence})
                continue
            else:
                evidence.append(f"L2: UNKNOWN — could not parse range \"{declared_range}\".")
                yield edge_event(dep_id, package_name, "L2", "unknown")
                yield log_event(f"  [{dep_name}] unparseable range \"{declared_range}\" — UNKNOWN", "warn")
                unknown_count += 1
                yield status_event(dep_id, "unknown", evidence)
                all_packages.append({"name": dep_name, "version": dep_ver, "role": "consumer",
                                      "in_tree": True, "declared_range": declared_range, "semver_admits": None,
                                      "symbol_reachable": None, "evidence": evidence})
                continue

            # L3: chain-walk reachability (single hop: dependent -> target)
            tarball_url = (manifest.get("dist") or {}).get("tarball")
            safe_fname = dep_name.replace("/", "__") + f"-{dep_ver}.tgz"
            tarball_path = TARBALL_DIR / safe_fname
            reachable = None
            if not tarball_url:
                evidence.append("L3: UNKNOWN — manifest had no downloadable tarball.")
                unknown_count += 1
            else:
                if not tarball_path.exists() or tarball_path.stat().st_size < 100:
                    try:
                        dl_resp = await client.get(tarball_url, timeout=20.0)
                        dl_resp.raise_for_status()
                        tarball_path.write_bytes(dl_resp.content)
                    except Exception as e:
                        evidence.append(f"L3: UNKNOWN — tarball download failed: {e}")
                        unknown_count += 1
                        tarball_path = None

                if tarball_path is not None and tarball_path.exists():
                    hop_result, hop_ev = check_hop(str(tarball_path), package_name)
                    evidence.append(f"L3 CHAIN WALK {dep_name}@{dep_ver} -> {package_name}: {hop_result.upper()} — {hop_ev}")
                    if hop_result == "unconditional":
                        reachable = True
                        symbol_reachable_count += 1
                    elif hop_result == "unknown":
                        reachable = None
                        unknown_count += 1
                    else:
                        reachable = False

            if reachable is True:
                evidence.append(
                    f"MITIGATION: {dep_name} itself has {dep_reach:,} downstream dependents — "
                    f"patching it cuts off exposure for all of them at once."
                    if dep_reach else
                    f"MITIGATION: {dep_name} has no known downstream dependents of its own — "
                    f"patching it only protects this one package."
                )
                yield edge_event(dep_id, package_name, "L3", "reachable")
                yield log_event(f"  [{dep_name}] REACHABLE — loads {package_name} unconditionally", "risk")
                yield status_event(dep_id, "reachable", evidence)
            elif reachable is None:
                yield edge_event(dep_id, package_name, "L3", "unknown")
                yield log_event(f"  [{dep_name}] L3 UNKNOWN — could not statically determine", "warn")
                yield status_event(dep_id, "unknown", evidence)
            else:
                yield edge_event(dep_id, package_name, "L3", "safe")
                yield log_event(f"  [{dep_name}] not reachable — filtered out at L3", "ok")
                yield status_event(dep_id, "safe", evidence)

            all_packages.append({"name": dep_name, "version": dep_ver, "role": "consumer",
                                  "in_tree": True, "declared_range": declared_range, "semver_admits": True,
                                  "symbol_reachable": reachable, "downstream_reach": dep_reach, "evidence": evidence})
            await asyncio.sleep(0.04)

        # Mitigation priority: among the reachable consumers, the ones that
        # themselves have the most downstream dependents are the highest-
        # leverage packages to patch first — fixing one there closes the
        # exposure for everything sitting behind it too.
        priority = sorted(
            (p for p in all_packages if p.get("symbol_reachable") is True),
            key=lambda p: p.get("downstream_reach", 0), reverse=True,
        )
        priority = [{"name": p["name"], "downstream_reach": p.get("downstream_reach", 0)} for p in priority]

        if priority:
            yield log_event("Mitigation priority — patch these first for the biggest reduction in exposure:", "risk")
            for p in priority[:5]:
                reach_note = f"feeds {p['downstream_reach']:,} more packages" if p["downstream_reach"] else "no further downstream reach"
                yield log_event(f"  {p['name']} — {reach_note}", "risk")

        yield log_event(
            f"Scan complete. In tree: {in_tree}  Semver admits: {semver_admits_count}  "
            f"Reachable: {symbol_reachable_count}  Unknown: {unknown_count}",
            "ok",
        )
        yield sse_event("final", {
            "package": package_name,
            "version": latest_ver,
            "compromised_version": compromised_version,
            "simulated": simulated,
            "advisories": vulns,
            "priority": priority,
            "counts": {
                "in_tree": in_tree,
                "semver_admits": semver_admits_count,
                "symbol_reachable": symbol_reachable_count,
                "unknown": unknown_count,
            },
            "packages": all_packages,
        })


@app.get("/api/scan/stream")
async def scan_stream(
    package: str = Query(..., min_length=1),
    mode: str = Query("real", pattern="^(real|simulate)$"),
    limit: int = Query(DEFAULT_CAP, ge=1, le=MAX_CAP),
):
    async def generator_with_error_handling():
        try:
            async for chunk in live_scan_generator(package.strip(), mode, limit):
                yield chunk
        except Exception as e:
            yield sse_event("log", {"level": "warn", "text": f"Scan error: {e}"})
            yield sse_event("final", {"error": str(e)})

    return StreamingResponse(
        generator_with_error_handling(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


# ── Static files (serve index.html and assets) ───────────────
app.mount("/", StaticFiles(directory=str(BASE_DIR), html=True), name="static")
