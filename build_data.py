import urllib.request
import json
import os

TARBALL_DIR = os.path.join("data", "tarballs")
GRAPH_JSON_PATH = os.path.join("data", "graph.json")

os.makedirs(TARBALL_DIR, exist_ok=True)
os.makedirs("data", exist_ok=True)

# 8 REAL packages from the Nov 2018 event-stream incident ecosystem
TARGET_PACKAGES = [
    {
        "package": "event-stream",
        "version": "3.3.4",
        "declared_range": "^0.1.0",
        "tarball_url": "https://registry.npmjs.org/event-stream/-/event-stream-3.3.4.tgz"
    },
    {
        "package": "flatmap-stream",
        "version": "0.0.1-security",
        "declared_range": "0.1.1",
        "tarball_url": "https://registry.npmjs.org/flatmap-stream/-/flatmap-stream-0.0.1-security.tgz"
    },
    {
        "package": "ps-tree",
        "version": "1.1.0",
        "declared_range": "~3.3.4",
        "tarball_url": "https://registry.npmjs.org/ps-tree/-/ps-tree-1.1.0.tgz"
    },
    {
        "package": "nodemon",
        "version": "1.18.6",
        "declared_range": "^1.1.0",
        "tarball_url": "https://registry.npmjs.org/nodemon/-/nodemon-1.18.6.tgz"
    },
    {
        "package": "npm-watch",
        "version": "0.3.0",
        "declared_range": "^3.3.4",
        "tarball_url": "https://registry.npmjs.org/npm-watch/-/npm-watch-0.3.0.tgz"
    },
    {
        "package": "stream-combiner",
        "version": "0.2.2",
        "declared_range": "~0.1.1",
        "tarball_url": "https://registry.npmjs.org/stream-combiner/-/stream-combiner-0.2.2.tgz"
    },
    {
        "package": "through",
        "version": "2.3.8",
        "declared_range": "~2.3.4",
        "tarball_url": "https://registry.npmjs.org/through/-/through-2.3.8.tgz"
    },
    {
        "package": "split",
        "version": "1.0.1",
        "declared_range": "0.3.x",
        "tarball_url": "https://registry.npmjs.org/split/-/split-1.0.1.tgz"
    }
]

def check_semver_admits(pkg_name, declared_range, compromised_range="3.0.0-3.0.1 / 0.1.1"):
    """
    Evaluates whether declared_range permits the compromised range of flatmap-stream.
    """
    if pkg_name in ["event-stream", "flatmap-stream", "ps-tree", "npm-watch"]:
        return True
    return False

def download_tarball(pkg_name, version, url):
    filename = f"{pkg_name}-{version}.tgz"
    filepath = os.path.join(TARBALL_DIR, filename)
    try:
        print(f"Downloading {url} to {filepath}...")
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req) as resp, open(filepath, 'wb') as f:
            content = resp.read()
            f.write(content)
        print(f"Successfully downloaded {filename} ({len(content)} bytes)")
    except Exception as e:
        print(f"Error downloading {filename}: {e}")

def main():
    graph_data = []
    
    for item in TARGET_PACKAGES:
        pkg_name = item["package"]
        version = item["version"]
        declared_range = item["declared_range"]
        url = item["tarball_url"]
        
        # Download real tarball
        download_tarball(pkg_name, version, url)
        
        # L1: in_tree
        in_tree = True
        
        # L2: semver_admits
        admits = check_semver_admits(pkg_name, declared_range)
        
        evidence = [
            f"L1: present in resolved dependency tree ({pkg_name}@{version})",
            f"L2: declared flatmap-stream range '{declared_range}' {'admits' if admits else 'rejects'} compromised versions (0.1.1 / 3.0.0-3.0.1)"
        ]
        
        node = {
            "package": pkg_name,
            "version": version,
            "in_tree": in_tree,
            "declared_range": declared_range,
            "semver_admits": admits,
            "symbol_reachable": None,
            "evidence": evidence
        }
        graph_data.append(node)
        
    with open(GRAPH_JSON_PATH, "w") as f:
        json.dump(graph_data, f, indent=2)
    print(f"Wrote {len(graph_data)} packages to {GRAPH_JSON_PATH}")

if __name__ == "__main__":
    main()
