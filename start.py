# RIPPLE — Start FastAPI server
#
# This replaces `python -m http.server 8000` from the original demo.
# The FastAPI server handles:
#   - Serving index.html + static assets (app.js, styles.css, etc.)
#   - GET /api/replay/event-stream-2018  → static funnel_result.json
#   - GET /api/scan/stream?package=NAME  → live SSE scan
#
# Usage:
#   python start.py
#   (then open http://localhost:8000)

import subprocess
import sys
import os

os.chdir(os.path.dirname(os.path.abspath(__file__)))
print("RIPPLE backend starting on http://localhost:8000 ...")
print("Open http://localhost:8000 in your browser.")
print("Press Ctrl+C to stop.")
print()

subprocess.run([sys.executable, "-m", "uvicorn", "server:app", "--port", "8000"])
