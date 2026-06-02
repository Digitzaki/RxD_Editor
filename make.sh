#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"

APP_NAME="RxD Hex Editor"
ENTRY="RxD Editor.py"
ICON="rxd.ico"

echo "Building ${APP_NAME}..."

/usr/bin/env python3 -m PyInstaller \
  --clean \
  --noconfirm \
  --onefile \
  --windowed \
  --name "${APP_NAME}" \
  --icon "${ICON}" \
  --add-data "${ICON}:." \
  --add-data "datainspect:datainspect" \
  --add-data "editor_themes.py:." \
  --add-data "action_scripts.py:." \
  --add-data "rxd_paths.py:." \
  --hidden-import "editor_themes" \
  --hidden-import "action_scripts" \
  --hidden-import "rxd_paths" \
  --hidden-import "performance_utils" \
  --hidden-import "datainspect" \
  --hidden-import "datainspect.data_inspector" \
  --hidden-import "datainspect.fields" \
  --hidden-import "datainspect.pattern_scan" \
  --hidden-import "datainspect.pointers" \
  --hidden-import "datainspect.statistics" \
  --hidden-import "PyQt5" \
  --hidden-import "PyQt5.QtCore" \
  --hidden-import "PyQt5.QtGui" \
  --hidden-import "PyQt5.QtWidgets" \
  --hidden-import "matplotlib.backends.backend_qt5agg" \
  --hidden-import "matplotlib.backends.backend_agg" \
  "${ENTRY}"

echo
echo "Build complete: dist/${APP_NAME}"
