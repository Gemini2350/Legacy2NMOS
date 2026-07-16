#!/bin/sh
# Build Legacy2NMOS.app for macOS. Requires: pip install pyinstaller
set -e
cd "$(dirname "$0")"
pyinstaller --noconfirm --clean --windowed \
  --name "Legacy2NMOS" \
  --add-data "legacy2nmos/ui:legacy2nmos/ui" \
  app.py
echo "Done: dist/Legacy2NMOS.app"
