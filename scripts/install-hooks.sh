#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial
# Copyright (c) 2026 USTechService Corporation
# Installs commitguard as a plain git pre-commit hook (no pre-commit framework needed).
set -e
root=$(git rev-parse --show-toplevel)
hook="$(git rev-parse --git-path hooks)/pre-commit"
mkdir -p "$(dirname "$hook")"
cat > "$hook" <<'HOOK'
#!/bin/sh
root=$(git rev-parse --show-toplevel)
for py in python3 python py; do
  if command -v "$py" >/dev/null 2>&1; then
    exec "$py" "$root/scripts/commitguard.py"
  fi
done
echo "commitguard: no Python found; install Python 3.9+" >&2
exit 1
HOOK
chmod +x "$hook"
echo "commitguard installed at $hook"
