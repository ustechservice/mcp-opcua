# Contributing

Thanks for helping improve mcp-opcua.

## Before you open a PR

1. **Sign the CLA.** Read [CLA.md](CLA.md) and check the CLA box in the PR template. PRs without it can't be merged, because the project is dual-licensed.
2. **Install the commit guard:**
   ```bash
   pip install pre-commit && pre-commit install
   # or, with no dependencies:
   sh scripts/install-hooks.sh        # macOS/Linux/Git Bash
   pwsh scripts/install-hooks.ps1     # Windows PowerShell
   ```
3. **Add license headers.** Every source file starts with:
   ```
   SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial
   Copyright (c) 2026 USTechService Corporation
   ```
   `python scripts/commitguard.py --fix-headers` adds it to staged files.

## Never commit

Model weights, checkpoints, datasets, `.env` files, keys, credentials, or customer data. The guard blocks these locally and CI blocks them again.

## Security issues

Don't open a public issue. See [SECURITY.md](SECURITY.md).
