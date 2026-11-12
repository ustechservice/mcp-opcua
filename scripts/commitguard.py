#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial
# Copyright (c) 2026 USTechService Corporation
"""commitguard: block model weights, datasets, secrets and unlicensed source from commits.

Modes:
  commitguard.py                 check staged files (plain git pre-commit hook)
  commitguard.py FILE...         check the given files (pre-commit framework)
  commitguard.py --all           check every tracked file (CI)
  commitguard.py --fix-headers   add missing SPDX headers to staged source files

Exceptions: add glob patterns to .commitguard-allow (one per line, # comments).
Never bypass with --no-verify; CI runs the same checks.
"""
from __future__ import annotations

import argparse
import fnmatch
import os
import re
import subprocess
import sys
from pathlib import Path, PurePosixPath

MAX_BYTES = 5 * 1024 * 1024  # 5 MB

SPDX_TAG = "SPDX-License-Identifier:"
HEADER_LINES = [
    "SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial",
    "Copyright (c) 2026 USTechService Corporation",
]

# Model weights, serialized objects, datasets.
BLOCKED_EXT = {
    ".pt", ".pth", ".ckpt", ".safetensors", ".onnx", ".h5", ".hdf5", ".keras",
    ".pkl", ".pickle", ".joblib", ".bin", ".gguf", ".ggml", ".tflite", ".pb",
    ".mlmodel", ".engine", ".plan", ".npy", ".npz", ".parquet", ".feather",
    ".arrow", ".tfrecord", ".lmdb", ".sqlite", ".sqlite3", ".db",
    ".pem", ".key", ".p12", ".pfx", ".jks", ".kdbx", ".ovpn", ".tfstate",
}
# Media is fine in docs, blocked elsewhere (keeps raw datasets out).
MEDIA_EXT = {".mp4", ".mov", ".avi", ".mkv", ".webm", ".wav", ".flac", ".mp3", ".m4a"}
MEDIA_OK_DIRS = {"docs", "assets", "examples", ".github"}

BLOCKED_DIRS = {"data", "datasets", "weights", "checkpoints", "private", "secrets", "runs", "wandb", "mlruns"}

BLOCKED_NAMES = [
    ".env", ".env.*", "*.env", "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519",
    "credentials.json", "service-account*.json", "*.tfvars", ".npmrc", ".pypirc",
    ".netrc", "kubeconfig", "*.kubeconfig",
]
NAME_EXCEPTIONS = ["*.example", "*.sample", "*.template", ".env.example"]

SECRET_PATTERNS = {
    "private key": re.compile(rb"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY"),
    "AWS access key": re.compile(rb"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
    "GitHub token": re.compile(rb"\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{60,})\b"),
    "Anthropic key": re.compile(rb"\bsk-ant-[A-Za-z0-9_\-]{20,}"),
    "OpenAI key": re.compile(rb"\bsk-(?!ant-)(?:proj-)?[A-Za-z0-9_\-]{32,}"),
    "Hugging Face token": re.compile(rb"\bhf_[A-Za-z0-9]{30,}\b"),
    "Slack token": re.compile(rb"\bxox[abprs]-[A-Za-z0-9\-]{10,}"),
    "Google API key": re.compile(rb"\bAIza[0-9A-Za-z_\-]{35}\b"),
    "Stripe live key": re.compile(rb"\b[rs]k_live_[0-9A-Za-z]{20,}"),
    "Discord bot token": re.compile(rb"\b[MNO][A-Za-z\d]{23,25}\.[\w-]{6}\.[\w-]{27,}"),
    "password assignment": re.compile(
        rb"(?i)\b(?:password|passwd|pwd|secret|api_?key|token)\s*[:=]\s*['\"][^'\"\s$<{]{8,}['\"]"
    ),
}

COMMENT_STYLE = {
    "#": {".py", ".sh", ".bash", ".rb", ".ps1", ".psm1", ".pl", ".r", ".jl", ".nim"},
    "//": {".rs", ".js", ".jsx", ".ts", ".tsx", ".go", ".cs", ".java", ".kt", ".swift",
           ".c", ".h", ".cc", ".cpp", ".hpp", ".scala", ".dart", ".zig", ".php"},
}
EXT_TO_COMMENT = {ext: c for c, exts in COMMENT_STYLE.items() for ext in exts}
HEADER_EXEMPT_DIRS = {"vendor", "third_party", "node_modules", "migrations"}


def git(*args: str) -> bytes:
    return subprocess.run(["git", *args], check=True, capture_output=True).stdout


def repo_root() -> Path:
    return Path(git("rev-parse", "--show-toplevel").decode().strip())


def load_allow(root: Path) -> list[str]:
    f = root / ".commitguard-allow"
    if not f.exists():
        return []
    lines = (l.split("#", 1)[0].strip() for l in f.read_text().splitlines())
    return [l for l in lines if l]


def matches(path: str, patterns: list[str]) -> bool:
    name = PurePosixPath(path).name
    return any(fnmatch.fnmatch(path, p) or fnmatch.fnmatch(name, p) for p in patterns)


class Source:
    """Reads file content either from the git index (staged) or the working tree."""

    def __init__(self, staged: bool):
        self.staged = staged

    def size(self, path: str) -> int:
        if self.staged:
            return int(git("cat-file", "-s", f":{path}"))
        return Path(path).stat().st_size

    def read(self, path: str) -> bytes:
        if self.staged:
            return git("cat-file", "-p", f":{path}")
        return Path(path).read_bytes()


def check_path(path: str) -> list[str]:
    p = PurePosixPath(path)
    ext = p.suffix.lower()
    parts = {s.lower() for s in p.parts[:-1]}
    problems = []
    if ext in BLOCKED_EXT:
        problems.append(f"blocked file type '{ext}' (weights/data/keys stay out of the repo)")
    if ext in MEDIA_EXT and not parts & MEDIA_OK_DIRS:
        problems.append(f"media file '{ext}' outside docs/assets/examples (possible dataset)")
    if bad := parts & BLOCKED_DIRS:
        problems.append(f"inside blocked directory '{sorted(bad)[0]}/'")
    if matches(path, BLOCKED_NAMES) and not matches(path, NAME_EXCEPTIONS):
        problems.append("credential/config file name")
    return problems


def check_content(path: str, data: bytes) -> list[str]:
    problems = []
    if b"\0" in data[:8192]:
        return problems  # binary: path/size rules already apply
    for label, rx in SECRET_PATTERNS.items():
        m = rx.search(data)
        if m:
            line = data.count(b"\n", 0, m.start()) + 1
            problems.append(f"possible {label} at line {line}")
    ext = PurePosixPath(path).suffix.lower()
    parts = {s.lower() for s in PurePosixPath(path).parts[:-1]}
    if ext in EXT_TO_COMMENT and not parts & HEADER_EXEMPT_DIRS and data.strip():
        if SPDX_TAG.encode() not in data[:2048]:
            problems.append("missing SPDX license header (run: python scripts/commitguard.py --fix-headers)")
    return problems


def add_header(path: Path) -> bool:
    c = EXT_TO_COMMENT.get(path.suffix.lower())
    if not c:
        return False
    text = path.read_text(encoding="utf-8")
    if SPDX_TAG in text[:2048]:
        return False
    header = "".join(f"{c} {l}\n" for l in HEADER_LINES)
    lines = text.splitlines(keepends=True)
    keep = 0
    if lines and lines[0].startswith("#!"):
        keep = 1
        if len(lines) > 1 and re.match(r"#.*coding[:=]", lines[1]):
            keep = 2
    path.write_text("".join(lines[:keep]) + header + "".join(lines[keep:]), encoding="utf-8")
    return True


def staged_files() -> list[str]:
    out = git("diff", "--cached", "--name-only", "--diff-filter=ACMR", "-z")
    return [f for f in out.decode().split("\0") if f]


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("files", nargs="*")
    ap.add_argument("--all", action="store_true", help="check all tracked files")
    ap.add_argument("--fix-headers", action="store_true", help="add missing SPDX headers to staged files")
    args = ap.parse_args()

    root = repo_root()
    if args.fix_headers:
        os.chdir(root)
        fixed = [f for f in staged_files() if Path(f).exists() and add_header(Path(f))]
        for f in fixed:
            print(f"header added: {f}")
        if fixed:
            subprocess.run(["git", "add", "--", *fixed], check=True)
        return 0

    if args.all:
        files = [f for f in git("ls-files", "-z").decode().split("\0") if f]
        src, base = Source(staged=False), root
    elif args.files:
        files, src, base = args.files, Source(staged=False), Path.cwd()
    else:
        files, src, base = staged_files(), Source(staged=True), root

    allow = load_allow(root)
    failures: dict[str, list[str]] = {}
    os.chdir(base)
    for f in files:
        rel = f.replace("\\", "/")
        if matches(rel, allow):
            continue
        if not src.staged and not Path(f).is_file():
            continue
        problems = check_path(rel)
        size = src.size(f)
        if size > MAX_BYTES:
            problems.append(f"file is {size / 1_048_576:.1f} MB (limit {MAX_BYTES // 1_048_576} MB; use Git LFS or keep private)")
        elif not problems:
            problems = check_content(rel, src.read(f))
        if problems:
            failures[rel] = problems

    if not failures:
        return 0
    print("\ncommitguard: commit blocked\n", file=sys.stderr)
    for f, probs in failures.items():
        for p in probs:
            print(f"  {f}: {p}", file=sys.stderr)
    print("\nFix the files, or add a reviewed glob to .commitguard-allow.\n", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
