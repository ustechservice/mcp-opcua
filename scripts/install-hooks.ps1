# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial
# Copyright (c) 2026 USTechService Corporation
# Installs commitguard as a git pre-commit hook on Windows (Git for Windows runs sh hooks).
$ErrorActionPreference = "Stop"
$hooks = git rev-parse --git-path hooks
New-Item -ItemType Directory -Force -Path $hooks | Out-Null
$hook = Join-Path $hooks "pre-commit"
@'
#!/bin/sh
root=$(git rev-parse --show-toplevel)
for py in python3 python py; do
  if command -v "$py" >/dev/null 2>&1; then
    exec "$py" "$root/scripts/commitguard.py"
  fi
done
echo "commitguard: no Python found; install Python 3.9+" >&2
exit 1
'@ -replace "`r`n", "`n" | Set-Content -NoNewline -Encoding ascii $hook
Write-Host "commitguard installed at $hook"
