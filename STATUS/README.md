Each agent writes ONLY to its own file: STATUS/data.md, STATUS/frontend.md,
STATUS/reachability.md. Never edit another agent's status file. The human
(you) reads all three before integrating.

Each status file, updated whenever something changes:
- STATE: not-started | in-progress | blocked | done
- BLOCKED-ON: (name a dependency, or "none")
- OUTPUT: (path to the file this agent has produced so far)
- ASSUMPTIONS: (anything guessed because the answer wasn't available yet)
- NEXT: (what happens next)
