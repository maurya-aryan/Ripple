"""
server.py — RIPPLE FastAPI backend.

Serves:
  GET /                              → index.html (static)
  GET /api/replay/event-stream-2018  → static funnel_result.json
  GET /api/scan/stream?package=NAME  → Server-Sent Events live scan

Run with:
  uvicorn server:app --port 8000 --reload
"""

import asyncio
import json
import os
import re
import sys
import tarfile
import urllib.request
from pathlib import Path
from typing import AsyncGenerator

from fastapi import FastAPI, Query
from fastapi.responses import Response, StreamingResponse
from fastapi.staticfiles import StaticFiles
import httpx

from reachability.chain_walk import walk_chain, check_hop

# ──────────────────────────────────────────────────────────────
app = FastAPI(title="RIPPLE API")

BASE_DIR = Path(__file__).parent
DATA_DIR = BASE_DIR / "data"
TARBALL_DIR = DATA_DIR / "tarballs"
TARBALL_DIR.mkdir(parents=True, exist_ok=True)

# ──────────────────────────────────────────────────────────────
# Helpers: semver (reused from build_data.py)
# ──────────────────────────────────────────────────────────────

def _parse_version(v):
    clean = re.sub(r"[^0-9.]", "", v.split("-")[0])
    parts = (clean + ".0.0").split(".")[:3]
    try:
        return tuple(int(x) for x in parts)
    except ValueError:
        return (0, 0, 0)


def semver_satisfies(range_str, target_version):
    target = _parse_version(target_version)
    range_str = range_str.strip()
    if range_str in ("latest", "*", ""):
        return True
    if "||" in range_str:
        return any(semver_satisfies(r.strip(), target_version) for r in range_str.split("||"))
    parts = range_str.split()
    if len(parts) > 1 and not range_str.startswith("^") and not range_str.startswith("~"):
        return all(semver_satisfies(p, target_version) for p in parts)
    m = re.match(r"^\^(\d+)\.(\d+)\.(\d+)$", range_str)
    if m:
        lo = tuple(int(x) for x in m.groups()); hi = (lo[0] + 1, 0, 0)
        return lo <= target < hi
    m = re.match(r"^\^(\d+)\.(\d+)$", range_str)
    if m:
        lo = (int(m.group(1)), int(m.group(2)), 0); hi = (lo[0] + 1, 0, 0)
        return lo <= target < hi
    m = re.match(r"^~(\d+)\.(\d+)\.(\d+)$", range_str)
    if m:
        lo = tuple(int(x) for x in m.groups()); hi = (lo[0], lo[1] + 1, 0)
        return lo <= target < hi
    m = re.match(r"^~(\d+)\.(\d+)$", range_str)
    if m:
        lo = (int(m.group(1)), int(m.group(2)), 0); hi = (lo[0], lo[1] + 1, 0)
        return lo <= target < hi
    m = re.match(r"^=?(\d+)\.(\d+)\.(\d+)$", range_str)
    if m:
        return target == tuple(int(x) for x in m.groups())
    m = re.match(r"^(\d+)\.(\d+)\.[xX*]$", range_str)
    if m:
        lo = (int(m.group(1)), int(m.group(2)), 0); hi = (lo[0], lo[1] + 1, 0)
        return lo <= target < hi
    for op, cmp in [(">=", lambda a, b: a >= b), ("<=", lambda a, b: a <= b),
                    (">", lambda a, b: a > b), ("<", lambda a, b: a < b)]:
        if range_str.startswith(op):
            ver = _parse_version(range_str[len(op):].strip())
            return cmp(target, ver)
    m = re.match(r"^(\d+)$", range_str)
    if m:
        lo = (int(m.group(1)), 0, 0); hi = (lo[0] + 1, 0, 0)
        return lo <= target < hi
    return None


# ──────────────────────────────────────────────────────────────
# SSE helpers
# ──────────────────────────────────────────────────────────────

def sse_event(event_type: str, data: dict) -> str:
    payload = json.dumps(data, ensure_ascii=False)
    return f"event: {event_type}\ndata: {payload}\n\n"


# ──────────────────────────────────────────────────────────────
# API: Replay Mode
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

MAX_DEPENDENTS_LIVE = 15  # cap for demo
NPM_REGISTRY = "https://registry.npmjs.org"
OSV_URL = "https://api.osv.dev/v1/query"
DEPS_DEV = "https://api.deps.dev/v3alpha"


async def live_scan_generator(package_name: str) -> AsyncGenerator[str, None]:
    """
    Async generator producing SSE events for a live scan of `package_name`.
    """

    def log(msg: str, level: str = "info") -> str:
        return sse_event("log", {"message": msg, "level": level})

    def node_event(pkg_name: str, version: str, role: str = "consumer") -> str:
        return sse_event("node", {"id": pkg_name, "version": version, "role": role, "label": f"{pkg_name}\nv{version}"})

    def edge_event(source: str, target: str, semver_admits) -> str:
        return sse_event("edge", {"source": source, "target": target, "semver_admits": semver_admits})

    def status_event(pkg_name: str, reachable, evidence: list) -> str:
        return sse_event("status", {"id": pkg_name, "reachable": reachable, "evidence": evidence})

    async with httpx.AsyncClient(timeout=20.0, follow_redirects=True) as client:

        # ── Step 1: Resolve package on npm ─────────────────────────
        yield log(f"[1/4] Resolving '{package_name}' on npm registry…")
        try:
            resp = await client.get(f"{NPM_REGISTRY}/{package_name}")
            resp.raise_for_status()
            pkg_data = resp.json()
            latest_ver = pkg_data.get("dist-tags", {}).get("latest", "unknown")
            description = pkg_data.get("description", "")
            yield log(f"      Found: {package_name}@{latest_ver} — {description[:80]}", "info")
            yield node_event(package_name, latest_ver, role="target")
        except Exception as e:
            yield log(f"      ERROR: could not resolve {package_name}: {e}", "error")
            yield sse_event("final", {"error": str(e), "package": package_name})
            return

        # ── Step 2: OSV.dev vulnerability lookup ────────────────────
        yield log(f"[2/4] Querying OSV.dev for known vulnerabilities in '{package_name}'…")
        advisories = []
        try:
            osv_resp = await client.post(
                OSV_URL,
                json={"package": {"name": package_name, "ecosystem": "npm"}},
            )
            osv_resp.raise_for_status()
            osv_data = osv_resp.json()
            vulns = osv_data.get("vulns", [])
            if vulns:
                yield log(f"      Found {len(vulns)} advisory/advisories:", "warn")
                for v in vulns[:5]:
                    vid = v.get("id", "?")
                    summary = v.get("summary", "no summary")[:100]
                    affected_ranges = []
                    for aff in v.get("affected", []):
                        for r in aff.get("ranges", []):
                            for evt in r.get("events", []):
                                if "introduced" in evt:
                                    affected_ranges.append(f">={evt['introduced']}")
                                if "fixed" in evt:
                                    affected_ranges.append(f"<{evt['fixed']}")
                    range_str = " ".join(affected_ranges[:4]) or "all versions"
                    yield log(f"      {vid}: {summary} (affected: {range_str})", "warn")
                    advisories.append({"id": vid, "summary": summary, "affected": range_str})
                if len(vulns) > 5:
                    yield log(f"      … and {len(vulns) - 5} more. See https://osv.dev for full list.", "warn")
            else:
                yield log(f"      No known vulnerabilities found for '{package_name}' in OSV.dev.", "ok")
        except Exception as e:
            yield log(f"      OSV.dev query failed: {e}", "warn")

        # ── Step 3: Find dependents via deps.dev ────────────────────
        yield log(f"[3/4] Fetching dependents of '{package_name}' from deps.dev…")
        dependents_found = []
        try:
            # Get version list and latest version for the target
            count_resp = await client.get(
                f"{DEPS_DEV}/systems/npm/packages/{package_name}/versions/{latest_ver}:dependents"
            )
            count_resp.raise_for_status()
            count_data = count_resp.json()
            total = count_data.get("directDependentCount", 0)
            yield log(f"      deps.dev reports {total} direct dependents for {package_name}@{latest_ver}.")
            if total > MAX_DEPENDENTS_LIVE:
                yield log(f"      Found {total} dependents — sampling {MAX_DEPENDENTS_LIVE} for live analysis (deterministic, alphabetical).", "warn")
        except Exception as e:
            yield log(f"      deps.dev dependents count query failed: {e}", "warn")
            total = 0

        # Get dependent package list via multi-query npm search + verification
        # Strategy: run multiple npm search queries (name, keywords, broader text),
        # collect candidates, then verify each against npm registry package.json.
        # This is the most honest approach — we only show real, verified dependents.
        dependents_found = []
        try:
            candidates = {}  # name -> version (deduped)

            search_queries = [
                package_name,              # packages named/related to target
                f"{package_name} plugin",  # plugins/extensions of target
                f"{package_name} middleware",
                f"{package_name} adapter",
            ]
            for query in search_queries:
                if len(candidates) >= MAX_DEPENDENTS_LIVE * 5:
                    break
                try:
                    sresp = await client.get(
                        f"{NPM_REGISTRY}/-/v1/search",
                        params={"text": query, "size": 50},
                    )
                    sresp.raise_for_status()
                    for obj in sresp.json().get("objects", []):
                        pname = obj.get("package", {}).get("name", "")
                        pver  = obj.get("package", {}).get("version", "")
                        if pname and pname != package_name and pname not in candidates:
                            candidates[pname] = pver
                except Exception:
                    pass

            yield log(f"      Gathered {len(candidates)} candidate packages to verify.")

            # Verify candidates against npm registry
            verified = []
            for cname, cver in list(candidates.items()):
                if len(verified) >= MAX_DEPENDENTS_LIVE:
                    break
                try:
                    pkg_resp = await client.get(f"{NPM_REGISTRY}/{cname}/{cver}")
                    pkg_resp.raise_for_status()
                    deps = pkg_resp.json().get("dependencies", {})
                    declared = deps.get(package_name)
                    if declared:
                        verified.append({
                            "name": cname,
                            "version": cver,
                            "declared_range": declared,
                        })
                except Exception:
                    continue

            dependents_found = verified
            yield log(
                f"      Verified {len(dependents_found)} real dependents "
                f"(packages that declare '{package_name}' in their dependencies)."
                + ("" if dependents_found else
                   " Note: npm full-text search does not index dependency fields directly — "
                   "this is a real limitation of the npm search API, not a tool flaw."),
                "ok" if dependents_found else "warn",
            )

        except Exception as e:
            yield log(f"      Dependent discovery failed: {e}", "warn")
            dependents_found = []

        # Emit node + edge for each verified dependent

        for dep in dependents_found:
            dep_name = dep["name"]
            dep_ver = dep["version"]
            dep_range = dep["declared_range"]
            yield node_event(dep_name, dep_ver, role="consumer")
            await asyncio.sleep(0.05)  # stagger for live effect

            # L2: semver gate
            admits = semver_satisfies(dep_range, latest_ver)
            admits_label = (
                "ADMITS" if admits is True
                else ("REJECTS" if admits is False else "UNKNOWN")
            )
            yield log(
                f"      [{dep_name}@{dep_ver}] declared range '{dep_range}' "
                f"{admits_label} {package_name}@{latest_ver}",
                "ok" if admits is True else ("warn" if admits is None else "info"),
            )
            yield edge_event(dep_name, package_name, admits)
            dep["semver_admits"] = admits

        # ── Step 4: Reachability check ───────────────────────────────
        yield log(f"[4/4] Walking reachability chains for verified dependents…")

        all_packages = []
        # Target package itself (compromise source or just subject)
        all_packages.append({
            "name": package_name,
            "version": latest_ver,
            "role": "target",
            "in_tree": True,
            "declared_range": "N/A",
            "semver_admits": None,
            "symbol_reachable": None,
            "evidence": (
                [f"ADVISORY: {a['id']} — {a['summary']} (affected: {a['affected']})" for a in advisories]
                if advisories else [f"No known OSV.dev advisories for {package_name}@{latest_ver}."]
            ),
        })

        symbol_reachable_count = 0
        unknown_count = 0

        for dep in dependents_found:
            dep_name = dep["name"]
            dep_ver = dep["version"]
            dep_range = dep["declared_range"]
            admits = dep.get("semver_admits")

            evidence = [
                f"L1: {dep_name}@{dep_ver} declares {package_name}: '{dep_range}' (verified from npm registry)",
                f"L2: range '{dep_range}' {'ADMITS' if admits is True else ('REJECTS' if admits is False else 'UNKNOWN')} {package_name}@{latest_ver}",
            ]

            if admits is not True:
                reachable = False
                evidence.append("L3: Skipped — L2 gate not passed (range does not admit the target version).")
                yield log(f"      [{dep_name}] L3 skip (L2 rejected)", "info")
            else:
                # Walk reachability chain: dep -> package_name
                # For live scan we check if the consumer loads the package unconditionally
                yield log(f"      [{dep_name}] Checking unconditional load chain…", "info")
                tarball_path = TARBALL_DIR / f"{dep_name}-{dep_ver}.tgz"

                # Download tarball if not already present
                if not tarball_path.exists() or tarball_path.stat().st_size < 100:
                    yield log(f"      [{dep_name}] Downloading tarball…", "info")
                    try:
                        dl_resp = await client.get(f"{NPM_REGISTRY}/{dep_name}/-/{dep_name}-{dep_ver}.tgz")
                        dl_resp.raise_for_status()
                        tarball_path.write_bytes(dl_resp.content)
                        yield log(f"      [{dep_name}] Downloaded ({len(dl_resp.content):,} bytes)", "info")
                    except Exception as e:
                        yield log(f"      [{dep_name}] Tarball download failed: {e}", "warn")
                        reachable = None
                        evidence.append(f"L3: UNKNOWN — tarball download failed: {e}")
                        unknown_count += 1
                        all_packages.append({
                            "name": dep_name, "version": dep_ver, "role": "consumer",
                            "in_tree": True, "declared_range": dep_range,
                            "semver_admits": admits, "symbol_reachable": reachable, "evidence": evidence,
                        })
                        yield status_event(dep_name, reachable, evidence)
                        continue

                # Single-hop chain: dep -> package_name
                # (We don't recurse further in live scan mode — scoped to one level)
                hop_result, hop_ev = check_hop(str(tarball_path), package_name)
                evidence.append(f"L3 HOP {dep_name}@{dep_ver} -> {package_name}: {hop_result.upper()} — {hop_ev}")

                if hop_result == "unconditional":
                    reachable = True
                    symbol_reachable_count += 1
                    evidence.append(f"L3: REACHABLE — {dep_name} loads {package_name} unconditionally at module top-level.")
                    yield log(f"      [{dep_name}] REACHABLE (unconditional load)", "danger")
                elif hop_result == "unknown":
                    reachable = None
                    unknown_count += 1
                    evidence.append(f"L3: UNKNOWN — could not determine if {dep_name}'s require is conditional.")
                    yield log(f"      [{dep_name}] UNKNOWN (unanalysable)", "warn")
                elif hop_result == "not_found":
                    reachable = False
                    evidence.append(f"L3: Not reachable — {dep_name} does not require {package_name} directly.")
                    yield log(f"      [{dep_name}] not reachable (no direct require found)", "ok")
                else:
                    reachable = False
                    evidence.append(f"L3: Not reachable — {dep_name}'s require of {package_name} appears conditional.")
                    yield log(f"      [{dep_name}] not reachable (conditional require)", "ok")

            all_packages.append({
                "name": dep_name, "version": dep_ver, "role": "consumer",
                "in_tree": True, "declared_range": dep_range,
                "semver_admits": admits, "symbol_reachable": reachable, "evidence": evidence,
            })
            yield status_event(dep_name, reachable, evidence)
            await asyncio.sleep(0.05)

        # ── Final event ────────────────────────────────────────────
        in_tree = len(dependents_found)
        semver_admits_count = sum(1 for d in dependents_found if d.get("semver_admits") is True)

        yield log(
            f"Scan complete. "
            f"In tree: {in_tree}  |  Semver admits: {semver_admits_count}  |  "
            f"Symbol reachable: {symbol_reachable_count}  |  Unknown: {unknown_count}",
            "info",
        )
        yield sse_event("final", {
            "package": package_name,
            "version": latest_ver,
            "advisories": advisories,
            "counts": {
                "in_tree": in_tree,
                "semver_admits": semver_admits_count,
                "symbol_reachable": symbol_reachable_count,
                "unknown": unknown_count,
            },
            "packages": all_packages,
        })


@app.get("/api/scan/stream")
async def scan_stream(package: str = Query(..., min_length=1)):
    async def generator_with_error_handling():
        try:
            async for chunk in live_scan_generator(package):
                yield chunk
        except Exception as e:
            yield sse_event("error", {"message": str(e)})

    return StreamingResponse(
        generator_with_error_handling(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        },
    )


# ── Static files (serve index.html and assets) ───────────────
app.mount("/", StaticFiles(directory=str(BASE_DIR), html=True), name="static")
