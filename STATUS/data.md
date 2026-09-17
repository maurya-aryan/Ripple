STATE: done
BLOCKED-ON: none
OUTPUT: data/graph.json
ASSUMPTIONS: Package list revised to ensure correct dependency direction (dependents of event-stream, not what event-stream depends on). Verified real consumer packages via registry.npmjs.org: ps-tree@1.1.0 (dependencies["event-stream"] = "~3.3.0"), live-server@1.2.0 (dependencies["event-stream"] = "latest"), and nodemon@1.12.5 (transitive consumer via ps-tree@^1.1.0). Added role="compromise_source" for event-stream@3.3.6 and flatmap-stream@0.1.1. Note: deps.dev's :dependents endpoint (v3alpha/systems/npm/packages/event-stream/versions/3.3.5:dependents) reports 1,170 direct dependents but returns aggregate counts rather than package lists; hence packages were verified directly against npm registry metadata.
NEXT: Agent-Reachability scans tarballs and excludes compromise sources from consumer funnel counts.
