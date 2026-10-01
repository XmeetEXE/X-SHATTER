#!/bin/sh
# X-SHATTER setup — checks for Node.js >= 20 (zero npm dependencies needed).
set -e
if ! command -v node >/dev/null 2>&1; then
  echo "ERROR: Node.js is not installed. Get it from https://nodejs.org/ (>= 20)."
  exit 1
fi
MAJOR=$(node -p "process.versions.node.split('.')[0]")
if [ "$MAJOR" -lt 20 ]; then
  echo "ERROR: Node.js >= 20 required (found $(node --version))."
  exit 1
fi
echo "OK: $(node --version) — no npm install needed (zero dependencies)."
echo ""
echo "CLI:        node src/cli.js --help"
echo "Dashboard:  node server.js   ->  http://127.0.0.1:4174/"
echo "Tests:      node --test \"test/*.test.js\""
