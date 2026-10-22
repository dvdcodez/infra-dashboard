#!/bin/bash
# macOS: double-click to start the dashboard and open it in the browser.
cd "$(dirname "$0")"
PORT=$(python3 -c "import json;print(json.load(open('settings.json')).get('port', 8796))" 2>/dev/null || echo 8796)
if curl -s -o /dev/null "http://127.0.0.1:$PORT/api/sync/status"; then open "http://127.0.0.1:$PORT/"; else python3 serve.py --open; fi
