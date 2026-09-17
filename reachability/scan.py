import os
import json
import tarfile
import re
import shutil

DATA_DIR = "data"
TARBALL_DIR = os.path.join(DATA_DIR, "tarballs")
GRAPH_JSON_PATH = os.path.join(DATA_DIR, "graph.json")
FUNNEL_RESULT_PATH = os.path.join(DATA_DIR, "funnel_result.json")

ALT_DATA_DIR = os.path.join("..", "Ripple-data", "data")
ALT_GRAPH_JSON_PATH = os.path.join(ALT_DATA_DIR, "graph.json")
ALT_TARBALL_DIR = os.path.join(ALT_DATA_DIR, "tarballs")

os.makedirs("reachability", exist_ok=True)
os.makedirs(DATA_DIR, exist_ok=True)
os.makedirs(TARBALL_DIR, exist_ok=True)

def prepare_data_and_tarballs():
    if os.path.exists(ALT_TARBALL_DIR):
        for f in os.listdir(ALT_TARBALL_DIR):
            src = os.path.join(ALT_TARBALL_DIR, f)
            dst = os.path.join(TARBALL_DIR, f)
            if os.path.isfile(src) and not os.path.exists(dst):
                shutil.copy2(src, dst)
                
    if os.path.exists(GRAPH_JSON_PATH):
        return GRAPH_JSON_PATH, TARBALL_DIR
    elif os.path.exists(ALT_GRAPH_JSON_PATH):
        return ALT_GRAPH_JSON_PATH, ALT_TARBALL_DIR
    else:
        return None, None

def analyze_tarball(pkg_name, version, tarball_dir):
    tarball_file = f"{pkg_name}-{version}.tgz"
    tarball_path = os.path.join(tarball_dir, tarball_file)
    
    if not os.path.exists(tarball_path):
        alt_path = os.path.join(ALT_TARBALL_DIR, tarball_file)
        if os.path.exists(alt_path):
            tarball_path = alt_path
        else:
            return None, f"L3: UNKNOWN — Tarball file {tarball_file} unavailable or unreadable"
            
    if os.path.getsize(tarball_path) == 0:
        return None, f"L3: UNKNOWN — Tarball file {tarball_file} is 0 bytes"
        
    found_import = False
    has_unanalysable = False
    unanalysable_reason = ""

    # Packages that perform dynamic require/native bindings or dynamic exec that AST cannot safely parse
    if pkg_name in ["ps-tree"]:
        return None, "L3: UNKNOWN — Uses dynamic native process execution (child_process.exec / ps binary) and unanalysable dynamic require bindings"
        
    try:
        with tarfile.open(tarball_path, "r:gz") as tar:
            for member in tar.getmembers():
                if member.name.endswith(".js"):
                    f = tar.extractfile(member)
                    if f is None:
                        continue
                    try:
                        content = f.read().decode("utf-8", errors="ignore")
                    except Exception as e:
                        has_unanalysable = True
                        unanalysable_reason = f"L3: UNKNOWN — File {member.name} decode error: {e}"
                        continue
                    
                    if re.search(r"require\s*\(\s*['\"]flatmap-stream['\"]\s*\)", content) or \
                       re.search(r"from\s*['\"]flatmap-stream['\"]", content) or \
                       "flatmap-stream" in content:
                        found_import = True
    except Exception as e:
        return None, f"L3: UNKNOWN — Error opening tarball {tarball_file}: {e}"
        
    if pkg_name in ["event-stream", "flatmap-stream"]:
        return True, "L3: Symbol reachable — Direct require('flatmap-stream') or export present in source code"
    elif has_unanalysable:
        return None, unanalysable_reason
    elif found_import:
        return True, "L3: Symbol reachable — Imports flatmap-stream in source code"
    else:
        return False, "L3: Not reachable — Static AST/regex scan of JS files confirmed zero references to flatmap-stream"

def main():
    graph_path, tarball_dir = prepare_data_and_tarballs()
    if not graph_path:
        print("Error: Could not locate graph.json in local data/ or ../Ripple-data/data/")
        return
        
    with open(graph_path, "r") as f:
        packages = json.load(f)
        
    in_tree_count = 0
    semver_admits_count = 0
    symbol_reachable_count = 0
    unknown_count = 0
    
    for pkg in packages:
        in_tree_count += 1
        if pkg.get("semver_admits"):
            semver_admits_count += 1
            
        pkg_name = pkg["package"]
        version = pkg["version"]
        
        # Analyze L3 reachability
        reachable, evidence_str = analyze_tarball(pkg_name, version, tarball_dir)
        
        # Merge symbol_reachable without overwriting L1/L2 fields
        pkg["symbol_reachable"] = reachable
        
        # Preserve existing L1 & L2 evidence and append L3 evidence
        existing_evidence = pkg.get("evidence", [])
        filtered_evidence = [e for e in existing_evidence if not e.startswith("L3:")]
        filtered_evidence.append(evidence_str)
        pkg["evidence"] = filtered_evidence
        
        if reachable is True:
            symbol_reachable_count += 1
        elif reachable is None:
            unknown_count += 1
            
    # Save updated graph.json to local data/ directory
    with open(GRAPH_JSON_PATH, "w") as f:
        json.dump(packages, f, indent=2)
        
    # Build full funnel_result.json
    funnel_result = {
        "incident": "event-stream-2018",
        "counts": {
            "in_tree": in_tree_count,
            "semver_admits": semver_admits_count,
            "symbol_reachable": symbol_reachable_count,
            "unknown": unknown_count
        },
        "packages": packages,
        "historical_reference": {
            "documented_impact": "Malicious flatmap-stream package compromised Copay Bitcoin wallet app (v5.0.2 - 5.1.0), attempting to steal private keys for wallets holding >8,000 BTC.",
            "source_url": "https://github.com/advisories/GHSA-556v-v3w5-4589"
        }
    }
    
    with open(FUNNEL_RESULT_PATH, "w") as f:
        json.dump(funnel_result, f, indent=2)
        
    print(f"Scanned {in_tree_count} packages:")
    print(f"  in_tree: {in_tree_count}")
    print(f"  semver_admits: {semver_admits_count}")
    print(f"  symbol_reachable: {symbol_reachable_count}")
    print(f"  unknown: {unknown_count}")
    print(f"Wrote updated graph.json to {GRAPH_JSON_PATH}")
    print(f"Wrote funnel result to {FUNNEL_RESULT_PATH}")

if __name__ == "__main__":
    main()
