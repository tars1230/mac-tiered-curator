#!/usr/bin/env python3
"""
mac-tiered-curator: macOS Tiered Multi-Volume & AI-Stack Disk Curator
=====================================================================
Synthesizes the best reverse-engineered mechanisms from MangoDisk v1.1.0
(REA Evidence IDs: ev_e1f6aba18fdd4bddacb6d5c7266e00a736a541c0fe1fb95e869b4b0176d2bb0a,
ev_c5c56ab70c3f4169483f66074d53e5deaf21778e9062e54f38e0cd55536d263f) and CleanMyMac,
specifically tailored for a tiered multi-volume macOS workstation
(/System/Volumes/Data + /Volumes/Cache + /Volumes/databox + /Volumes/archive)
and heavy AI Agent workflows (Codex, Hermes, OpenClaw, WorkBuddy, Cline, OpenCode, Antigravity).

Hardened after dual independent reviews by Cline CLI (v3.0.70) and OpenCode CLI (v1.18.18):
1. Kernel `statfs` Filesystem Type Guard: Uses `libc.statfs` (`f_fstypename` & `MNT_LOCAL`)
   in addition to name blacklists to strictly skip WebDAV/SMB/NFS/AFP/network mounts.
2. Strict Prefix & Subtree Protection: Blocks both exact `PROTECTED_ROOTS` and all descendants
   of `PROTECTED_SUBTREE_PREFIXES` (`~/Documents/*`, `~/Desktop/*`, `~/Pictures/*`, `~/Movies/*`, `~/Music/*`, `~/CloudMounts/*`).
3. Dual-Path Validation: `is_safe_to_modify` requires BOTH logical and resolved real paths to
   reside within allowed prefixes (unless `check_link_self=True` for atomic symlink repair).
4. Atomic Symlink Re-binding: Uses temporary symlink + `os.replace()` instead of non-atomic `unlink` + `symlink`.
5. Lock-Safe SQLite Discovery & VACUUM: Dynamically discovers Agent SQLite DBs and handles active WAL/locks gracefully.
"""

from __future__ import annotations

import argparse
import collections
import ctypes
import hashlib
import ctypes.util
import dataclasses
import json
import os
import plistlib
import shutil
import sqlite3
import subprocess
import sys
import time
import urllib.parse
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# ---------------------------------------------------------------------------
# Constants, Filesystem Guards & Reverse-Engineered Catalog Definitions
# ---------------------------------------------------------------------------

NETWORK_DIR_BLACKLIST = {
    "CloudMounts",
    ".Spotlight-V100",
    ".fseventsd",
    ".DocumentRevisions-V100",
    ".TemporaryItems",
}

NETWORK_FSTYPES = {
    "webdav",
    "smbfs",
    "nfs",
    "afpfs",
    "cifs",
    "ftp",
    "fusefs",
    "osxfuse",
    "macfuse",
}

MNT_LOCAL = 0x00001000

PROTECTED_ROOTS = {
    "/",
    "/System",
    "/System/Volumes",
    "/System/Volumes/Data",
    "/Applications",
    "/Library",
    "/Users",
    "/Volumes",
    "/Volumes/Cache",
    "/Volumes/databox",
    "/Volumes/archive",
    "/private",
    "/var",
    "/etc",
    "/usr",
    "/bin",
    "/sbin",
    str(Path.home()),
    str(Path.home() / "Library"),
    str(Path.home() / "Applications"),
}

PROTECTED_SUBTREE_PREFIXES = tuple(
    str(Path.home() / sub)
    for sub in ("Documents", "Desktop", "Pictures", "Movies", "Music", "CloudMounts")
)


class _StatfsDarwin(ctypes.Structure):
    """macOS arm64/x86_64 `struct statfs` layout (`_DARWIN_FEATURE_64_BIT_INODE`)."""
    _fields_ = [
        ("f_bsize", ctypes.c_uint32),
        ("f_iosize", ctypes.c_int32),
        ("f_blocks", ctypes.c_uint64),
        ("f_bfree", ctypes.c_uint64),
        ("f_bavail", ctypes.c_uint64),
        ("f_files", ctypes.c_uint64),
        ("f_ffree", ctypes.c_uint64),
        ("f_fsid", ctypes.c_uint64),
        ("f_owner", ctypes.c_uint32),
        ("f_type", ctypes.c_uint32),
        ("f_flags", ctypes.c_uint32),
        ("f_fssubtype", ctypes.c_uint32),
        ("f_fstypename", ctypes.c_char * 16),
        ("f_mntonname", ctypes.c_char * 1024),
        ("f_mntfromname", ctypes.c_char * 1024),
        ("f_flags_ext", ctypes.c_uint32),
        ("f_reserved", ctypes.c_uint32 * 7),
    ]


_LIBC = ctypes.CDLL(ctypes.util.find_library("c") or "/usr/lib/libSystem.B.dylib", use_errno=True)
_STATFS_FN = getattr(_LIBC, "statfs", None)
if _STATFS_FN is not None:
    _STATFS_FN.argtypes = [ctypes.c_char_p, ctypes.POINTER(_StatfsDarwin)]
    _STATFS_FN.restype = ctypes.c_int


def get_filesystem_info(path_str: str) -> Optional[Tuple[str, bool, str]]:
    """
    Returns `(fstypename, is_local, mount_point)` via macOS `statfs`, or None on error.
    """
    if _STATFS_FN is None:
        return None
    buf = _StatfsDarwin()
    rc = _STATFS_FN(os.fsencode(path_str), ctypes.byref(buf))
    if rc != 0:
        return None
    fstype = buf.f_fstypename.decode("utf-8", errors="ignore").strip("\x00").lower()
    mnton = buf.f_mntonname.decode("utf-8", errors="ignore").strip("\x00")
    is_local = bool(buf.f_flags & MNT_LOCAL) and (fstype not in NETWORK_FSTYPES)
    return fstype, is_local, mnton


def is_local_filesystem(path_str: str) -> bool:
    """Returns True only if `path_str` (or its existing parent) is on a local non-network filesystem."""
    target = path_str
    if not os.path.exists(target):
        target = os.path.dirname(os.path.abspath(target))
    info = get_filesystem_info(target)
    if info is None:
        return False
    _, is_local, _ = info
    return is_local


# Reverse-engineered from MangoDisk `project_artifact_schema.rs` (31 project types)
PROJECT_ARTIFACT_RULES: List[Dict[str, Any]] = [
    {"id": "project.rust", "markers": ["Cargo.toml"], "artifacts": ["target", ".xwin-cache"]},
    {"id": "project.node", "markers": ["package.json"], "artifacts": ["node_modules", ".next/cache", ".angular/cache", ".turbo"]},
    {"id": "project.python", "markers": ["pyproject.toml", "setup.py", "requirements.txt"], "artifacts": [".pytest_cache", ".mypy_cache", ".ruff_cache", "__pycache__", ".tox"]},
    {"id": "project.cmake", "markers": ["CMakeLists.txt"], "artifacts": ["cmake-build-debug", "cmake-build-release"]},
    {"id": "project.flutter", "markers": ["pubspec.yaml"], "artifacts": [".dart_tool", "build"]},
    {"id": "project.swift", "markers": ["Package.swift"], "artifacts": [".build", ".swiftpm"]},
    {"id": "project.gradle", "markers": ["build.gradle", "build.gradle.kts"], "artifacts": [".gradle", "build"]},
    {"id": "project.zig", "markers": ["build.zig"], "artifacts": [".zig-cache", "zig-cache", "zig-out"]},
    {"id": "project.go", "markers": ["go.mod"], "artifacts": ["bin"]},
]

# Reverse-engineered from MangoDisk `declarative_catalog.rs` + Local AI Agent & /Volumes/Cache rules
CLEANUP_RULES: List[Dict[str, Any]] = [
    # --- Local AI Agent Stack (WorkBuddy, Hermes, Codex, OpenClaw, Cline, OpenCode, Antigravity) ---
    {
        "id": "ai.workbuddy-logs",
        "category": "ai_agent",
        "risk": "safe",
        "default_selected": True,
        "description": "WorkBuddy runtime & debug logs (~/.workbuddy/logs)",
        "paths": ["~/.workbuddy/logs"],
    },
    {
        "id": "ai.workbuddy-cache",
        "category": "ai_agent",
        "risk": "safe",
        "default_selected": True,
        "description": "WorkBuddy offloaded cache & session code cache",
        "paths": [
            "~/.workbuddy/cache",
            "~/.workbuddy/app/session/Cache",
            "~/.workbuddy/app/session/Code Cache",
        ],
    },
    {
        "id": "ai.hermes-checkpoints",
        "category": "ai_agent",
        "risk": "recoverable",
        "default_selected": False,
        "description": "Hermes temporary checkpoints (~/.hermes/checkpoints; preserves ~/.hermes/work project reviews)",
        "paths": ["~/.hermes/checkpoints"],
    },
    {
        "id": "ai.codex-archived-and-backups",
        "category": "ai_agent",
        "risk": "safe",
        "default_selected": True,
        "description": "Codex archived sessions, crashpad, backup states & Sparkle/URL caches",
        "paths": [
            "~/.codex/archived_sessions",
            "~/.codex/backups_state",
            "~/Library/Application Support/Codex/Crashpad/pending",
            "~/Library/Caches/Codex",
            "~/Library/Caches/com.openai.codex",
        ],
    },
    {
        "id": "ai.openclaw-logs-and-cache",
        "category": "ai_agent",
        "risk": "safe",
        "default_selected": True,
        "description": "OpenClaw logs and external /Volumes/Cache/openclaw staging",
        "paths": ["~/.openclaw/logs", "/Volumes/Cache/openclaw"],
    },
    {
        "id": "ai.opencode-and-cline-cache",
        "category": "ai_agent",
        "risk": "safe",
        "default_selected": True,
        "description": "OpenCode Desktop & Cline rendering/Chromium caches (preserves task & session data)",
        "paths": [
            "~/Library/Caches/ai.opencode.desktop",
            "~/Library/Application Support/ai.opencode.desktop/Cache",
            "~/Library/Application Support/ai.opencode.desktop/Code Cache",
            "~/Library/Application Support/ai.opencode.desktop/GPUCache",
            "~/Library/Application Support/ai.opencode.desktop/DawnGraphiteCache",
            "~/Library/Application Support/ai.opencode.desktop/DawnWebGPUCache",
        ],
    },
    {
        "id": "ai.antigravity-rendering-cache",
        "category": "ai_agent",
        "risk": "safe",
        "default_selected": False,  # Host IDE runtime; opt-in when Antigravity is closed
        "description": "Antigravity Chromium Cache/Code Cache & VSIX cache (preserves brain/config)",
        "paths": [
            "~/Library/Application Support/Antigravity/Cache",
            "~/Library/Application Support/Antigravity/Code Cache",
            "~/Library/Application Support/Antigravity/GPUCache",
            "~/Library/Application Support/Antigravity/CachedExtensionVSIXs",
        ],
    },
    {
        "id": "ai.huggingface-xet-cache",
        "category": "ai_agent",
        "risk": "safe",
        "default_selected": True,
        "description": "HuggingFace Xet transfer chunk/shard caches (preserves hub models)",
        "paths": [
            "~/.cache/huggingface/xet/chunk_cache",
            "~/.cache/huggingface/xet/shard_cache",
            "~/.cache/huggingface/xet/logs",
        ],
    },
    # --- External /Volumes/Cache Offloaded Developer Caches ---
    {
        "id": "cache_vol.npm-cache",
        "category": "external_cache",
        "risk": "recoverable",
        "default_selected": True,
        "description": "NPM tarball _cacache & _logs on system & /Volumes/Cache/npm-cache (preserves _npx)",
        "paths": ["~/.npm/_cacache", "/Volumes/Cache/npm-cache/_cacache", "/Volumes/Cache/npm-cache/_logs"],
    },
    {
        "id": "cache_vol.pip-cache",
        "category": "external_cache",
        "risk": "recoverable",
        "default_selected": True,
        "description": "Python pip HTTP/wheel cache (preserves uv hardlinked environments)",
        "paths": [
            "~/Library/Caches/pip",
        ],
    },
    {
        "id": "cache_vol.go-and-cargo",
        "category": "external_cache",
        "risk": "recoverable",
        "default_selected": True,
        "description": "Go build cache & Cargo registry cache",
        "paths": [
            "~/Library/Caches/go-build",
            "/Volumes/Cache/go-build",
            "~/.cargo/registry/cache",
        ],
    },
    {
        "id": "cache_vol.playwright-and-browser",
        "category": "external_cache",
        "risk": "recoverable",
        "default_selected": False,
        "description": "Playwright browser binaries & /Volumes/Cache/browser",
        "paths": [
            "~/Library/Caches/ms-playwright",
            "/Volumes/Cache/ms-playwright",
            "/Volumes/Cache/browser",
        ],
    },
    {
        "id": "cache_vol.conda-and-homebrew-pkgs",
        "category": "external_cache",
        "risk": "recoverable",
        "default_selected": True,
        "description": "Conda tarball cache & Homebrew bottle download cache on /Volumes/Cache",
        "paths": [
            "/Volumes/Cache/conda-pkgs/cache",
            "/Volumes/Cache/homebrew-cache",
            "~/Library/Caches/Homebrew",
        ],
    },
    # --- Desktop Apps & Browsers (MangoDisk Declarative Catalog) ---
    {
        "id": "app.browsers-cache",
        "category": "application",
        "risk": "safe",
        "default_selected": True,
        "description": "Chrome, Edge, Chromium, Brave, Arc network & GPU shader caches",
        "paths": [
            "~/Library/Caches/Google/Chrome",
            "~/Library/Application Support/Google/Chrome/ShaderCache",
            "~/Library/Caches/Microsoft Edge",
            "~/Library/Caches/Chromium",
            "~/Library/Caches/company.thebrowser.Browser",
        ],
    },
    {
        "id": "app.domestic-office-cache",
        "category": "application",
        "risk": "safe",
        "default_selected": True,
        "description": "DingTalk, Lark/Feishu, WeChat, IMA Copilot, QQ, WPS rendering & Sparkle caches",
        "paths": [
            "~/Library/Application Support/DingTalkMac/log",
            "~/Library/Application Support/DingTalkMac/activitylog",
            "~/Library/Application Support/DingTalkMac/holmeslogs",
            "~/Library/Caches/com.alibaba.DingTalkMac/WebKit/NetworkCache",
            "~/Library/Caches/LarkShell/aha/users",
            "~/Library/Caches/com.tencent.xinWeChat",
            "~/Library/Caches/com.tencent.imamac",
            "~/Library/Caches/com.kingsoft.wpsoffice.mac",
        ],
    },
    {
        "id": "system.quicklook-and-help-cache",
        "category": "system",
        "risk": "safe",
        "default_selected": True,
        "description": "macOS QuickLook thumbnail & helpd caches",
        "paths": [
            "~/Library/Caches/com.apple.QuickLook.thumbnailcache",
            "~/Library/Caches/com.apple.helpd",
        ],
    },
    {
        "id": "system.user-diagnostic-logs",
        "category": "system",
        "risk": "recoverable",
        "default_selected": False,
        "description": "User application logs in ~/Library/Logs (opt-in to preserve recent crash reports)",
        "paths": ["~/Library/Logs"],
    },
    {
        "id": "ai.openclaw-dead-browser-profile",
        "category": "ai_agent",
        "risk": "safe",
        "default_selected": True,
        "description": "Retired OpenClaw Douyin Playwright Chromium profile (.douyin-pw-profile) & runtime tmp/cache",
        "paths": [
            "~/.openclaw/workspace/.douyin-pw-profile",
            "~/.openclaw/cache",
            "~/.openclaw/tmp",
        ],
    },
    {
        "id": "app.123pan-client-cache",
        "category": "app",
        "risk": "safe",
        "default_selected": True,
        "description": "123pan desktop client Electron HTTP/Code/GPU caches and C++ logs on system disk",
        "paths": [
            "~/Library/Application Support/123pan/Cache",
            "~/Library/Application Support/123pan/Code Cache",
            "~/Library/Application Support/123pan/GPUCache",
            "~/Library/Application Support/123pan/DawnCache",
            "~/Library/Application Support/123pan/CPP/Logs",
        ],
    },
    {
        "id": "app.uuremote-updater-and-logs",
        "category": "app",
        "risk": "safe",
        "default_selected": True,
        "description": "NetEase UURemote downloaded updater packages and diagnostic logs",
        "paths": [
            "~/Library/Application Support/com.netease.uuremote.updater/download",
            "~/Library/Application Support/com.netease.uuremote.updater/Logs",
            "~/Library/Application Support/com.netease.uuremote/Logs",
        ],
    },
    {
        "id": "dev.dot-cache-regenerable",
        "category": "dev",
        "risk": "safe",
        "default_selected": True,
        "description": "Regenerable tool caches inside ~/.cache and ~/.hermes/cache/uv (Puppeteer, Hermes npm/uv, OpenCode, MiMoCode)",
        "paths": [
            "~/.cache/puppeteer",
            "~/.cache/hermes-npm-cache",
            "~/.cache/hermes-uv-cache",
            "~/.cache/opencode",
            "~/.cache/mimocode",
            "~/.hermes/cache/uv",
        ],
    },
    {
        "id": "ai.workbuddy-cli-connector-cache",
        "category": "ai_agent",
        "risk": "safe",
        "default_selected": True,
        "description": "WorkBuddy embedded Node CLI connector npm cache (_cacache & _npx)",
        "paths": [
            "~/.workbuddy/binaries/node/cli-connector-cache/_cacache",
            "~/.workbuddy/binaries/node/cli-connector-cache/_npx",
        ],
    },
    {
        "id": "cache_vol.browser-updater-crx",
        "category": "external_cache",
        "risk": "safe",
        "default_selected": True,
        "description": "GoogleUpdater & EdgeUpdater downloaded CRX package caches on /Volumes/Cache/app",
        "paths": [
            "/Volumes/Cache/app/EdgeUpdater/crx_cache",
            "/Volumes/Cache/app/GoogleUpdater/crx_cache",
        ],
    },
    {
        "id": "app.cursor-shipit-update",
        "category": "application",
        "risk": "safe",
        "default_selected": True,
        "description": "Cursor & Sand desktop ShipIt post-update staging residue in ~/Library/Caches",
        "paths": [
            "~/Library/Caches/com.todesktop.230313mzl4w4u92.ShipIt",
            "~/Library/Caches/com.anysphere.sand.ShipIt",
        ],
    },
    {
        "id": "app.opencode-desktop-updater",
        "category": "application",
        "risk": "safe",
        "default_selected": True,
        "description": "OpenCode desktop Electron updater staging and downloaded zip in ~/Library/Caches",
        "paths": [
            "~/Library/Caches/@opencode-aidesktop-updater",
        ],
    },
]

# Cold-Tier Archive & Relocate Rules (Backed by /Volumes/archive safety-net & /Volumes/databox APFS fallback)
# Dynamically configurable via environment variables for custom multi-volume setups
ARCHIVE_VAULT_ROOT = os.environ.get("CURATOR_ARCHIVE_ROOT", "/Volumes/archive/from-databox/app/archives")
DATABOX_ARCHIVE_FALLBACK = os.environ.get("CURATOR_DATABOX_ARCHIVE", "/Volumes/databox/app/archives")
ARCHIVE_MANIFEST_DIR = os.environ.get("CURATOR_ARCHIVE_MANIFEST", "/Volumes/archive/from-databox/app/archives/_manifests")

ARCHIVE_RULES: List[Dict[str, Any]] = [
    {
        "id": "archive.cache-iso-staging",
        "op": "move+symlink",
        "min_age_days": 0,
        "description": "Migrate cold ISO/USB boot backups from /Volumes/Cache/iso-staging to /Volumes/archive with symlink",
        "sources": ["/Volumes/Cache/iso-staging/win11-usb-boot-backup"],
        "dest_subdir": "cache-iso",
    },
    {
        "id": "archive.cache-cold-unity",
        "op": "move+symlink",
        "min_age_days": 30,
        "description": "Migrate dormant /Volumes/Cache/app/Unity (>30d) to /Volumes/archive with symlink",
        "sources": ["/Volumes/Cache/app/Unity"],
        "dest_subdir": "cache-cold-apps",
    },
    {
        "id": "archive.cache-cold-ml",
        "op": "move+symlink",
        "min_age_days": 30,
        "description": "Migrate dormant ML models (/Volumes/Cache/ml >30d) to /Volumes/archive with symlink",
        "sources": ["/Volumes/Cache/ml"],
        "dest_subdir": "cache-cold-ml",
    },
    {
        "id": "archive.hermes-checkpoints",
        "op": "move+symlink",
        "min_age_days": 14,
        "description": "Migrate Hermes checkpoints (~/.hermes/checkpoints) to /Volumes/archive with symlink",
        "sources": ["~/.hermes/checkpoints"],
        "dest_subdir": "hermes-cold",
    },
    {
        "id": "archive.hermes-cold-work",
        "op": "move+symlink",
        "min_age_days": 25,
        "scan_children_of": "~/.hermes/work",
        "description": "Migrate completed Hermes work review directories (>25d) to archive with symlink",
        "dest_subdir": "hermes-work",
    },
    {
        "id": "archive.home-cold-workspaces",
        "op": "move+symlink",
        "min_age_days": 25,
        "description": "Migrate cold Home workspaces (~/episodes, ~/workbuddy-sync, ~/elder-memoir >25d) to archive with symlink",
        "sources": ["~/episodes", "~/workbuddy-sync", "~/elder-memoir"],
        "dest_subdir": "home-cold",
    },
    {
        "id": "archive.downloads-cold-installers",
        "op": "move_cold",
        "min_age_days": 14,
        "scan_installers_in": "~/Downloads",
        "description": "Move standalone cold installers (.dmg/.pkg/.apk/.iso >14d, >=20MB) in ~/Downloads to /Volumes/archive/from-databox/app/archives/downloads-cold",
        "dest_subdir": "downloads-cold",
    },
    {
        "id": "archive.databox-retired-staging",
        "op": "move_cold",
        "min_age_days": 20,
        "description": "Consolidate symlink-free retired archive folders from /Volumes/databox/app/archives to /Volumes/archive",
        "sources": [
            "/Volumes/databox/app/archives/cache-tmp-20260905",
            "/Volumes/databox/app/archives/uv-cache",
        ],
        "dest_subdir": "databox-consolidated",
    },
    {
        "id": "archive.workbuddy-old-logs",
        "op": "move_cold",
        "min_age_days": 7,
        "scan_children_of": "~/.workbuddy/logs",
        "include_child_files": True,
        "description": "Archive aged WorkBuddy log directories/files (>7d) to /Volumes/archive runtime-hygiene",
        "dest_subdir": "runtime-hygiene/workbuddy-logs",
    },
    {
        "id": "archive.workbuddy-old-traces",
        "op": "move_cold",
        "min_age_days": 7,
        "scan_children_of": "~/.workbuddy/traces",
        "include_child_files": True,
        "description": "Archive aged WorkBuddy trace directories/files (>7d) to /Volumes/archive runtime-hygiene",
        "dest_subdir": "runtime-hygiene/workbuddy-traces",
    },
    {
        "id": "archive.openclaw-old-backups",
        "op": "move_cold",
        "min_age_days": 21,
        "scan_children_of": "~/.openclaw/backups",
        "include_child_files": True,
        "description": "Archive aged OpenClaw backups (>21d) to /Volumes/archive runtime-hygiene",
        "dest_subdir": "runtime-hygiene/openclaw-backups",
    },
    {
        "id": "archive.dot-cache-codex-runtimes",
        "op": "move+symlink",
        "min_age_days": 0,
        "target_root": "/Volumes/Cache/cache",
        "description": "Offload ~/.cache/codex-runtimes (1.5 GB) from system disk to /Volumes/Cache/cache with symlink",
        "sources": ["~/.cache/codex-runtimes"],
        "dest_subdir": "dot-cache-offload",
    },
    {
        "id": "archive.openclaw-sealed-copies",
        "op": "move+symlink",
        "min_age_days": 0,
        "description": "Seal retired OpenClaw copies (~/.mimocode, /Volumes/Cache/app/openclaw, and dormant ~/.openclaw data/state/memory subdirs) to archive while preserving active skill/venv symlinks",
        "sources": [
            "~/.mimocode",
            "/Volumes/Cache/app/openclaw",
            "~/.openclaw/memory",
            "~/.openclaw/state",
            "~/.openclaw/Video",
            "~/.openclaw/workspace/data",
            "~/.openclaw/workspace/微信入口",
            "~/.openclaw/workspace/reports",
            "~/.openclaw/workspace/logs",
        ],
        "dest_subdir": "openclaw-sealed",
    },
    {
        "id": "archive.codex-retired-dirs",
        "op": "move+symlink",
        "min_age_days": 30,
        "description": "Archive dormant ~/.codex-session-delete and ~/.codex-redteam (>30d) from system disk to archive with symlink",
        "sources": [
            "~/.codex-session-delete",
            "~/.codex-redteam",
        ],
        "dest_subdir": "codex-retired",
    },
    {
        "id": "archive.home-root-node-modules",
        "op": "move+symlink",
        "min_age_days": 7,
        "description": "Relocate root ~/node_modules (1.6 GB) from system disk to APFS archive tier with symlink",
        "sources": ["~/node_modules"],
        "dest_subdir": "home-node-modules",
    },
    {
        "id": "archive.cache-older-hermes-backups",
        "op": "move_cold",
        "min_age_days": 0,
        "description": "Relocate pre-salvage Hermes DB backup snapshot (/Volumes/Cache/backups/hermes-20261012, 3.9 GB) from /Volumes/Cache to /Volumes/archive",
        "sources": ["/Volumes/Cache/backups/hermes-20261012"],
        "dest_subdir": "hermes-backups",
    },
    {
        "id": "archive.hermes-corrupt-db-snapshots",
        "op": "move_cold",
        "min_age_days": 0,
        "description": "Cold-archive unreferenced ~/.hermes/state.db.corrupt-* snapshots (2.1 GB) from system disk to /Volumes/archive",
        "sources": ["~/.hermes/state.db.corrupt-20261012"],
        "dest_subdir": "hermes-backups",
    },
    {
        "id": "archive.workbuddy-cold-sessions",
        "op": "move+symlink",
        "min_age_days": 10,
        "description": "Relocate dormant July 2026 WorkBuddy timestamped session directories (~5.1 GB) to APFS archive tier with symlink",
        "sources": [
            "~/Workbuddy/2026-07-10-20-33-14",
            "~/Workbuddy/2026-07-02-23-06-22",
            "~/Workbuddy/2026-07-06-11-01-33",
            "~/Workbuddy/2026-07-02-14-07-22",
        ],
        "dest_subdir": "workbuddy-cold-sessions",
    },
]

# Reverse-engineered from MangoDisk `mangodisk_platform::macos::system_maintenance` (0x100ee63d8)
MAINTENANCE_TASKS: Dict[str, Dict[str, Any]] = {
    "dns-cache": {
        "title": "Flush DNS Cache & Reload mDNSResponder",
        "requires_sudo": True,
        "cmd": "/usr/bin/dscacheutil -flushcache; /usr/bin/killall -HUP mDNSResponder",
    },
    "quicklook-cache": {
        "title": "Reset QuickLook Server & Thumbnail Cache",
        "requires_sudo": False,
        "cmd": "/usr/bin/qlmanage -r && /usr/bin/qlmanage -r cache",
    },
    "launch-services": {
        "title": "Rebuild LaunchServices Open-With Menu Database",
        "requires_sudo": False,
        "cmd": "/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister -kill -r -domain local -domain system -domain user",
    },
    "audio-service": {
        "title": "Restart CoreAudio Daemon (Fixes audio glitches)",
        "requires_sudo": True,
        "cmd": "/usr/bin/killall coreaudiod",
    },
    "finder-service": {
        "title": "Restart Finder",
        "requires_sudo": False,
        "cmd": "/usr/bin/killall Finder",
    },
    "verify-startup-disk": {
        "title": "Verify APFS Startup Volume Integrity (Live Read-Only)",
        "requires_sudo": False,
        "cmd": "/usr/sbin/diskutil verifyVolume /",
    },
    "spotlight-index": {
        "title": "Rebuild Spotlight Index on Root Volume",
        "requires_sudo": True,
        "cmd": "/usr/bin/mdutil -E /",
    },
}


# ---------------------------------------------------------------------------
# Data Models
# ---------------------------------------------------------------------------

@dataclass
class VolumeStatus:
    mount_point: str
    tier_role: str
    fstype: str
    is_local: bool
    total_bytes: int
    used_bytes: int
    avail_bytes: int
    capacity_pct: float
    health_level: str  # "healthy" | "elevated" | "critical"


@dataclass
class ScanCandidate:
    rule_id: str
    category: str
    risk: str
    description: str
    logical_path: str
    resolved_path: str
    is_symlink_root: bool
    physical_volume: str
    allocated_bytes: int
    file_count: int
    truncated: bool = False


@dataclass
class BrokenSymlinkRecord:
    link_path: str
    old_target: str
    suggested_new_target: Optional[str]
    status: str  # "repairable" | "orphaned"


@dataclass
class ArchiveCandidate:
    rule_id: str
    op: str  # "move+symlink" | "move_cold"
    description: str
    source_path: str
    source_volume: str
    dest_path: str
    dest_volume: str
    allocated_bytes: int
    file_count: int
    internal_symlinks: int
    age_days: float


# ---------------------------------------------------------------------------
# Core Helper Functions
# ---------------------------------------------------------------------------

def format_bytes(num_bytes: int) -> str:
    val = float(max(0, num_bytes))
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if val < 1024.0 or unit == "TB":
            return f"{val:.1f} {unit}" if unit != "B" else f"{int(val)} B"
        val /= 1024.0
    return f"{val:.1f} PB"


def resolve_volume_for_path(path_str: str) -> str:
    """Determines which physical volume a resolved path resides on."""
    try:
        real = os.path.realpath(path_str)
    except Exception:
        real = path_str
    info = get_filesystem_info(real)
    if info is not None and info[2]:
        mnt = info[2]
        if mnt == "/":
            return "/System/Volumes/Data"
        return mnt
    for vol in ("/Volumes/Cache", "/Volumes/databox", "/Volumes/archive"):
        if real == vol or real.startswith(vol + "/"):
            return vol
    if real.startswith("/Volumes/"):
        parts = real.split("/")
        if len(parts) >= 3:
            return "/" + "/".join(parts[1:3])
    return "/System/Volumes/Data"


def _path_violates_protected_or_blacklist(p: str) -> bool:
    if p in PROTECTED_ROOTS:
        return True
    for blk in NETWORK_DIR_BLACKLIST:
        if f"/{blk}/" in (p + "/"):
            return True
    for protected_sub in PROTECTED_SUBTREE_PREFIXES:
        if p == protected_sub or p.startswith(protected_sub + "/"):
            return True
    return False


def is_safe_to_modify(
    path_str: str,
    allow_external_volumes: bool = True,
    check_link_self: bool = False,
) -> bool:
    """
    Hardened guardrail:
    1. Rejects exact `PROTECTED_ROOTS`, `NETWORK_DIR_BLACKLIST` segments, and all descendants
       of `PROTECTED_SUBTREE_PREFIXES` (`~/Documents`, `~/Desktop`, `~/Pictures`, `~/Movies`, `~/Music`, `~/CloudMounts`).
    2. Requires BOTH `norm` (logical path) AND `real` (resolved target) to reside within `allowed_prefixes`
       and on a local filesystem (`is_local_filesystem`), preventing symlink-escape attacks.
    3. When `check_link_self=True` (used ONLY when re-binding/removing a broken symlink itself without touching its target),
       validates `norm` and its parent directory's resolved path.
    """
    if not path_str:
        return False
    norm = os.path.normpath(os.path.abspath(path_str))
    if _path_violates_protected_or_blacklist(norm):
        return False

    home = str(Path.home())
    allowed_prefixes = [home + "/"]
    if allow_external_volumes:
        allowed_prefixes.extend([
            "/Volumes/Cache/",
            "/Volumes/databox/",
            "/Volumes/archive/",
        ])

    if not any(norm.startswith(prefix) for prefix in allowed_prefixes):
        return False

    if check_link_self:
        parent_real = os.path.normpath(os.path.realpath(os.path.dirname(norm)))
        if _path_violates_protected_or_blacklist(parent_real):
            return False
        if not any(parent_real == prefix.rstrip("/") or parent_real.startswith(prefix) for prefix in allowed_prefixes):
            return False
        return is_local_filesystem(parent_real)

    real = os.path.normpath(os.path.realpath(norm))
    if _path_violates_protected_or_blacklist(real):
        return False
    if not any(real.startswith(prefix) for prefix in allowed_prefixes):
        return False
    if not is_local_filesystem(real):
        return False
    return True


def measure_directory_fast(
    root_path: str,
    budget_seconds: float = 1.2,
    follow_root_symlink: bool = True,
) -> Tuple[int, int, bool]:
    """
    Fast bounded directory size measurement using physical 512-byte blocks (`st_blocks * 512`),
    skipping sparse holes and network mounts. Mirrors MangoDisk `allocated_content` behavior.
    """
    t0 = time.monotonic()
    total_bytes = 0
    file_count = 0
    truncated = False

    if not os.path.lexists(root_path):
        return 0, 0, False

    try:
        st = os.stat(root_path, follow_symlinks=follow_root_symlink)
    except OSError:
        return 0, 0, False

    target_root = os.path.realpath(root_path) if follow_root_symlink else root_path
    if not is_local_filesystem(target_root):
        return 0, 0, False

    if not os.path.isdir(target_root):
        return st.st_blocks * 512, 1, False

    stack = [target_root]
    while stack:
        if (time.monotonic() - t0) > budget_seconds:
            truncated = True
            break
        current = stack.pop()
        try:
            with os.scandir(current) as it:
                for entry in it:
                    if (time.monotonic() - t0) > budget_seconds:
                        truncated = True
                        break
                    if entry.name in NETWORK_DIR_BLACKLIST:
                        continue
                    try:
                        if entry.is_symlink():
                            continue
                        if entry.is_dir(follow_symlinks=False):
                            stack.append(entry.path)
                        elif entry.is_file(follow_symlinks=False):
                            est = entry.stat(follow_symlinks=False)
                            total_bytes += est.st_blocks * 512
                            file_count += 1
                    except OSError:
                        continue
        except OSError:
            continue

    return total_bytes, file_count, truncated


# ---------------------------------------------------------------------------
# 1. Multi-Volume Tiered Status
# ---------------------------------------------------------------------------

def inspect_cloud_tier(auto_heal: bool = False) -> Optional[VolumeStatus]:
    """
    Zero-traversal health check for Tier 4 (`~/CloudMounts/123pan` WebDAV).
    Reads `/sbin/mount` and `~/Library/Application Support/123pan-mount/status.txt`
    without performing any `statvfs` or `scandir` on the WebDAV mount point.
    """
    home = str(Path.home())
    mount_pt = os.path.join(home, "CloudMounts", "123pan")
    helper = os.path.join(home, "Library", "Application Support", "123pan-mount", "mount-123pan-webdav")
    status_file = os.path.join(home, "Library", "Application Support", "123pan-mount", "status.txt")

    if not os.path.exists(os.path.join(home, "CloudMounts")) and not os.path.exists(helper):
        return None

    mounted = False
    try:
        proc = subprocess.run(["/sbin/mount"], capture_output=True, text=True, timeout=2.0, check=False)
        mounted = f" on {mount_pt} (" in proc.stdout and "webdav" in proc.stdout.lower()
    except Exception:
        mounted = False

    if not mounted and auto_heal and os.path.isfile(helper) and os.access(helper, os.X_OK):
        try:
            subprocess.run(["/bin/zsh", "-f", helper], timeout=20.0, check=False)
            proc = subprocess.run(["/sbin/mount"], capture_output=True, text=True, timeout=2.0, check=False)
            mounted = f" on {mount_pt} (" in proc.stdout and "webdav" in proc.stdout.lower()
        except Exception:
            pass

    state_str = "healthy" if mounted else "elevated"
    if os.path.isfile(status_file):
        try:
            with open(status_file, "r", encoding="utf-8", errors="ignore") as f:
                txt = f.read()
            if "state=error" in txt and not mounted:
                state_str = "critical"
        except OSError:
            pass

    return VolumeStatus(
        mount_point="~/CloudMounts/123pan",
        tier_role=f"Tier 4: Cloud Offsite Vault (123pan WebDAV: {'ONLINE' if mounted else 'OFFLINE'})",
        fstype="webdav",
        is_local=False,
        total_bytes=0,
        used_bytes=0,
        avail_bytes=0,
        capacity_pct=0.0,
        health_level=state_str,
    )


def inspect_volumes(include_cloud_tier: bool = True, auto_heal_cloud: bool = False) -> List[VolumeStatus]:
    tiers = [
        ("/System/Volumes/Data", "Tier 0: System & Home Data"),
        (os.environ.get("CURATOR_CACHE_VOLUME", "/Volumes/Cache"), "Tier 1: High-Speed Scratch & Cache"),
        (os.environ.get("CURATOR_DATABOX_VOLUME", "/Volumes/databox"), "Tier 2: Hot Media, Apps & Active Projects"),
        (os.environ.get("CURATOR_ARCHIVE_VOLUME", "/Volumes/archive"), "Tier 3: Cold Archive Storage"),
    ]

    # Automatically discover other mounted local volumes under /Volumes for custom user setups
    standard_mounts = {t[0] for t in tiers}
    if os.path.isdir("/Volumes"):
        try:
            for entry in os.scandir("/Volumes"):
                if entry.name.startswith(".") or not entry.is_dir(follow_symlinks=False):
                    continue
                m_path = entry.path
                if m_path in standard_mounts or not os.path.ismount(m_path):
                    continue
                fs_info = get_filesystem_info(m_path)
                if fs_info and fs_info[1]:  # is_local
                    tiers.append((m_path, f"Tier 2+: External Disk ({entry.name})"))
        except OSError:
            pass

    results: List[VolumeStatus] = []
    for mount, role in tiers:
        if not os.path.exists(mount):
            continue
        try:
            fs_info = get_filesystem_info(mount)
            fstype = fs_info[0] if fs_info else "apfs"
            is_local = fs_info[1] if fs_info else True
            usage = shutil.disk_usage(mount)
            used = usage.total - usage.free
            pct = (used / usage.total * 100.0) if usage.total else 0.0
            if pct >= 82.0:
                health = "critical"
            elif pct >= 72.0:
                health = "elevated"
            else:
                health = "healthy"
            results.append(
                VolumeStatus(
                    mount_point=mount,
                    tier_role=role,
                    fstype=fstype,
                    is_local=is_local,
                    total_bytes=usage.total,
                    used_bytes=used,
                    avail_bytes=usage.free,
                    capacity_pct=round(pct, 1),
                    health_level=health,
                )
            )
        except OSError:
            continue
    if include_cloud_tier:
        cloud_status = inspect_cloud_tier(auto_heal=auto_heal_cloud)
        if cloud_status is not None:
            results.append(cloud_status)
    return results


# ---------------------------------------------------------------------------
# 2. Symlink-Aware Cleanup Scanner & Executor
# ---------------------------------------------------------------------------

def scan_cleanup_candidates(budget_per_path: float = 1.0) -> List[ScanCandidate]:
    candidates: List[ScanCandidate] = []
    for rule in CLEANUP_RULES:
        for raw_p in rule["paths"]:
            expanded = os.path.expanduser(raw_p)
            if not os.path.lexists(expanded):
                continue
            is_link = os.path.islink(expanded)
            resolved = os.path.realpath(expanded)
            if not os.path.exists(resolved):
                continue
            # Pre-validate safety & local filesystem before scanning
            if not is_safe_to_modify(expanded, allow_external_volumes=True):
                continue
            sz, cnt, trunc = measure_directory_fast(resolved, budget_seconds=budget_per_path, follow_root_symlink=True)
            if sz <= 0:
                continue
            vol = resolve_volume_for_path(resolved)
            candidates.append(
                ScanCandidate(
                    rule_id=rule["id"],
                    category=rule["category"],
                    risk=rule["risk"],
                    description=rule["description"],
                    logical_path=expanded,
                    resolved_path=resolved,
                    is_symlink_root=is_link,
                    physical_volume=vol,
                    allocated_bytes=sz,
                    file_count=cnt,
                    truncated=trunc,
                )
            )
    candidates.sort(key=lambda c: c.allocated_bytes, reverse=True)
    return candidates


def clean_directory_contents_preserving_root(target_dir: str, dry_run: bool = True) -> Tuple[int, int]:
    """
    Cleans the contents inside `target_dir` while preserving `target_dir` itself
    (so any symlink pointing to `target_dir` remains 100% intact).
    Returns (released_bytes, deleted_entries).
    """
    if not is_safe_to_modify(target_dir):
        raise ValueError(f"Refusing to modify protected or out-of-scope path: {target_dir}")

    real_target = os.path.realpath(target_dir)
    if not is_safe_to_modify(real_target):
        raise ValueError(f"Refusing to modify protected resolved path: {real_target}")

    before_bytes, before_files, _ = measure_directory_fast(real_target, budget_seconds=2.5)
    if dry_run:
        return before_bytes, before_files

    deleted_items = 0
    if os.path.isfile(real_target) and not os.path.islink(target_dir):
        try:
            os.unlink(real_target)
            deleted_items += 1
        except OSError:
            pass
    elif os.path.isdir(real_target):
        with os.scandir(real_target) as it:
            for entry in it:
                if entry.name in NETWORK_DIR_BLACKLIST:
                    continue
                try:
                    if entry.is_symlink() or entry.is_file(follow_symlinks=False):
                        os.unlink(entry.path)
                        deleted_items += 1
                    elif entry.is_dir(follow_symlinks=False):
                        shutil.rmtree(entry.path, ignore_errors=True)
                        deleted_items += 1
                except OSError:
                    continue

    after_bytes, _, _ = measure_directory_fast(real_target, budget_seconds=1.5)
    return max(0, before_bytes - after_bytes), deleted_items


# ---------------------------------------------------------------------------
# 3. Broken Symlink Detector & Atomic Cross-Volume Auto-Healer
# ---------------------------------------------------------------------------

def _auto_safe_prefix_block(path_str: str) -> Optional[str]:
    """String-only forbidden prefix. Does not stat, list, or open the path."""
    if not path_str:
        return None
    raw = os.path.expanduser(path_str)
    if not os.path.isabs(raw):
        raw = os.path.abspath(raw)
    norm = os.path.normpath(raw)
    home = str(Path.home())
    checks = (
        ("/Volumes/DataPool", "datapool"),
        (os.path.join(home, "Documents"), "documents"),
        (os.path.join(home, "CloudMounts"), "network_volume"),
        (os.path.join(home, ".hermes"), "hermes"),
    )
    for prefix, reason in checks:
        if norm == prefix or norm.startswith(prefix + os.sep):
            return reason
    return None


def scan_broken_symlinks(
    search_roots: Optional[List[str]] = None,
    replacement_candidates: Optional[List[Tuple[str, str]]] = None,
    replacement_Candidates: Optional[List[Tuple[str, str]]] = None,  # Backwards-compat alias
    allow_datapool_rewrite: bool = True,
    avoid_forbidden_prefixes: bool = False,
) -> List[BrokenSymlinkRecord]:
    """
    Detects broken symlinks. While `/Volumes/DataPool` is mounted it is not a
    retired disk: those prefixes are not rewritten onto databox or archive.
    `allow_datapool_rewrite=False` keeps that rewrite off even when DataPool
    is unmounted. `avoid_forbidden_prefixes=True` records DataPool, Documents,
    CloudMounts, and Hermes hits without stating or descending into them.
    """
    home = str(Path.home())
    if search_roots is None:
        search_roots = [
            home,
            os.path.join(home, "Desktop"),
            os.path.join(home, "Downloads"),
            os.path.join(home, "Applications"),
            os.path.join(home, "Library", "Application Support"),
        ]
    repls = replacement_candidates or replacement_Candidates
    if repls is None:
        repls = [
            ("/Volumes/databox/archive/", "/Volumes/archive/from-databox/archive/"),
            ("/Volumes/databox/app/archives/", "/Volumes/archive/from-databox/app/archives/"),
        ]
        if allow_datapool_rewrite and not os.path.ismount("/Volumes/DataPool"):
            repls.extend([
                ("/Volumes/DataPool/archive/", "/Volumes/archive/from-databox/archive/"),
                ("/Volumes/DataPool/app/archives/", "/Volumes/archive/from-databox/app/archives/"),
                ("/Volumes/DataPool/", "/Volumes/databox/"),
                ("/Volumes/DataPool/", "/Volumes/archive/"),
                ("/Volumes/DataPool", "/Volumes/databox"),
                ("/Volumes/DataPool", "/Volumes/archive"),
            ])

    records: List[BrokenSymlinkRecord] = []
    seen = set()

    for root in search_roots:
        if not os.path.exists(root):
            continue
        if avoid_forbidden_prefixes and _auto_safe_prefix_block(os.path.abspath(root)):
            continue
        try:
            with os.scandir(root) as it:
                for entry in it:
                    if not entry.is_symlink():
                        continue
                    if entry.path in seen:
                        continue
                    seen.add(entry.path)
                    if entry.name.startswith("Singleton") or entry.name.startswith("RunningChrome"):
                        continue
                    try:
                        raw_target = os.readlink(entry.path)
                    except OSError:
                        continue
                    abs_target = (
                        raw_target
                        if os.path.isabs(raw_target)
                        else os.path.normpath(os.path.join(os.path.dirname(entry.path), raw_target))
                    )
                    if avoid_forbidden_prefixes and (
                        _auto_safe_prefix_block(entry.path) or _auto_safe_prefix_block(abs_target)
                    ):
                        records.append(
                            BrokenSymlinkRecord(
                                link_path=entry.path,
                                old_target=raw_target,
                                suggested_new_target=None,
                                status="forbidden",
                            )
                        )
                        continue
                    if os.path.exists(abs_target):
                        continue

                    suggested: Optional[str] = None
                    for old_prefix, new_prefix in repls:
                        if abs_target.startswith(old_prefix):
                            candidate = new_prefix + abs_target[len(old_prefix):]
                            if os.path.exists(candidate) and is_local_filesystem(candidate):
                                suggested = candidate
                                break
                    records.append(
                        BrokenSymlinkRecord(
                            link_path=entry.path,
                            old_target=raw_target,
                            suggested_new_target=suggested,
                            status="repairable" if suggested else "orphaned",
                        )
                    )
        except OSError:
            continue

    return records


def repair_or_remove_broken_symlinks(
    records: List[BrokenSymlinkRecord],
    remove_orphans: bool = False,
    dry_run: bool = True,
) -> Dict[str, int]:
    """
    Atomically repairs broken symlinks using a temporary sibling symlink + `os.replace()`
    so an interrupted operation never leaves a missing link.
    """
    stats = {"repaired": 0, "removed": 0, "skipped": 0}
    for rec in records:
        if rec.status == "forbidden":
            stats["skipped"] += 1
            continue
        # Allow modifying broken symlinks in home/Downloads/Desktop via check_link_self=True
        parent_dir = os.path.dirname(os.path.abspath(rec.link_path))
        if not os.path.islink(rec.link_path) or not is_local_filesystem(parent_dir):
            stats["skipped"] += 1
            continue
        if rec.suggested_new_target and os.path.exists(rec.suggested_new_target) and is_local_filesystem(rec.suggested_new_target):
            if not dry_run:
                tmp_link = f"{rec.link_path}.curator-tmp-{os.getpid()}"
                try:
                    if os.path.lexists(tmp_link):
                        os.unlink(tmp_link)
                    os.symlink(rec.suggested_new_target, tmp_link)
                    os.replace(tmp_link, rec.link_path)
                finally:
                    if os.path.lexists(tmp_link):
                        try:
                            os.unlink(tmp_link)
                        except OSError:
                            pass
            stats["repaired"] += 1
        elif remove_orphans:
            if not dry_run:
                os.unlink(rec.link_path)
            stats["removed"] += 1
        else:
            stats["skipped"] += 1
    return stats


# ---------------------------------------------------------------------------
# 4. Dynamic AI Agent SQLite Bloat & Freelist Analyzer
# ---------------------------------------------------------------------------

def discover_agent_sqlite_paths() -> List[str]:
    """Dynamically discovers SQLite databases across Hermes, Codex, Cline, OpenCode, and WorkBuddy."""
    home = Path.home()
    explicit = [
        home / ".hermes" / "state.db",
        home / ".codex" / "logs_2.sqlite",
        home / ".codex" / "thread_history_1.sqlite",
        home / ".codex" / "sqlite" / "codex-thread-summaries-dev.db",
    ]
    search_dirs = [
        home / ".hermes",
        home / ".codex",
        home / ".cline",
        home / ".config" / "opencode",
        home / ".local" / "share" / "opencode",
        home / "Library" / "Application Support" / "ai.opencode.desktop",
    ]
    found: Dict[str, Path] = {}
    for p in explicit:
        if p.is_file():
            found[str(p.resolve())] = p

    for d in search_dirs:
        if not d.is_dir():
            continue
        try:
            with os.scandir(d) as it:
                for entry in it:
                    if (
                        not entry.name.startswith("._")
                        and entry.is_file(follow_symlinks=False)
                        and (entry.name.endswith(".db") or entry.name.endswith(".sqlite") or entry.name.endswith(".sqlite3"))
                    ):
                        rp = os.path.realpath(entry.path)
                        found.setdefault(rp, Path(entry.path))
        except OSError:
            continue
    return [str(v) for v in found.values()]


def analyze_sqlite_databases(custom_paths: Optional[List[str]] = None) -> List[Dict[str, Any]]:
    paths = [os.path.expanduser(p) for p in custom_paths] if custom_paths is not None else discover_agent_sqlite_paths()
    results = []
    for p in paths:
        if not os.path.isfile(p) or not is_local_filesystem(p):
            continue
        try:
            st = os.stat(p)
            size_bytes = st.st_blocks * 512
            uri_path = urllib.parse.quote(os.path.abspath(p))
            uri = f"file:{uri_path}?mode=ro"
            conn = sqlite3.connect(uri, uri=True, timeout=1.5)
            cur = conn.cursor()
            page_size = int(cur.execute("PRAGMA page_size;").fetchone()[0])
            page_count = int(cur.execute("PRAGMA page_count;").fetchone()[0])
            freelist_count = int(cur.execute("PRAGMA freelist_count;").fetchone()[0])
            conn.close()
            reclaimable_bytes = freelist_count * page_size
            results.append({
                "path": p,
                "allocated_bytes": size_bytes,
                "page_size": page_size,
                "page_count": page_count,
                "freelist_pages": freelist_count,
                "reclaimable_bytes": reclaimable_bytes,
            })
        except Exception as exc:
            results.append({
                "path": p,
                "allocated_bytes": os.path.getsize(p) if os.path.exists(p) else 0,
                "reclaimable_bytes": 0,
                "error": str(exc),
            })
    results.sort(key=lambda x: (x.get("reclaimable_bytes", 0), x.get("allocated_bytes", 0)), reverse=True)
    return results


def vacuum_sqlite_database_safe(db_path: str, dry_run: bool = True) -> Dict[str, Any]:
    """
    Runs `PRAGMA wal_checkpoint(TRUNCATE)` + `VACUUM` with lock/busy exception handling.
    """
    if not os.path.isfile(db_path) or not is_local_filesystem(db_path):
        return {"path": db_path, "status": "skipped", "reason": "not_local_file"}
    before = os.stat(db_path).st_blocks * 512
    if dry_run:
        return {"path": db_path, "status": "dry_run", "before_bytes": before}
    try:
        conn = sqlite3.connect(db_path, timeout=3.0)
        conn.execute("PRAGMA wal_checkpoint(TRUNCATE);")
        conn.execute("VACUUM;")
        conn.close()
        after = os.stat(db_path).st_blocks * 512
        return {
            "path": db_path,
            "status": "vacuumed",
            "before_bytes": before,
            "after_bytes": after,
            "saved_bytes": max(0, before - after),
        }
    except sqlite3.Error as exc:
        return {
            "path": db_path,
            "status": "locked_or_busy",
            "before_bytes": before,
            "error": str(exc),
        }


# ---------------------------------------------------------------------------
# 5. Project Build Artifact Scanner (Reverse-engineered from `project_artifacts.rs`)
# ---------------------------------------------------------------------------

def scan_project_artifacts(
    roots: Optional[List[str]] = None,
    min_stale_days: int = 7,
    max_depth: int = 3,
) -> List[Dict[str, Any]]:
    home = str(Path.home())
    if roots is None:
        roots = [
            home,
            os.path.join(home, "Documents"),
            os.path.join(home, "Workbuddy"),
            "/Volumes/databox",
        ]
    now = time.time()
    findings: List[Dict[str, Any]] = []
    visited_dirs = set()

    def walk_projects(curr: str, depth: int) -> None:
        if depth > max_depth:
            return
        real_curr = os.path.realpath(curr)
        if real_curr in visited_dirs or not is_local_filesystem(real_curr):
            return
        visited_dirs.add(real_curr)

        try:
            entries = {e.name: e for e in os.scandir(curr)}
        except OSError:
            return

        for rule in PROJECT_ARTIFACT_RULES:
            if any(m in entries for m in rule["markers"]):
                for art_rel in rule["artifacts"]:
                    art_path = os.path.join(curr, art_rel)
                    if os.path.isdir(art_path) and not os.path.islink(art_path):
                        try:
                            mtime = os.path.getmtime(art_path)
                            stale_days = (now - mtime) / 86400.0
                            if stale_days >= min_stale_days:
                                sz, cnt, trunc = measure_directory_fast(art_path, budget_seconds=0.8)
                                if sz >= 10 * 1024 * 1024:  # >= 10 MB
                                    findings.append({
                                        "rule_id": rule["id"],
                                        "project_root": curr,
                                        "artifact_path": art_path,
                                        "stale_days": round(stale_days, 1),
                                        "allocated_bytes": sz,
                                        "file_count": cnt,
                                        "truncated": trunc,
                                    })
                        except OSError:
                            pass

        skip_names = NETWORK_DIR_BLACKLIST | {
            "node_modules", "target", ".git", "Library", "Applications",
            "Trash", ".Trash", ".cache", ".npm", ".cargo", ".hermes", ".codex",
        }
        for name, entry in entries.items():
            if name.startswith(".") or name in skip_names:
                continue
            try:
                if entry.is_dir(follow_symlinks=False):
                    walk_projects(entry.path, depth + 1)
            except OSError:
                continue

    for r in roots:
        if os.path.isdir(r):
            walk_projects(r, 0)

    findings.sort(key=lambda x: x["allocated_bytes"], reverse=True)
    return findings


# ---------------------------------------------------------------------------
# 6. macOS Container Leftover Detector (Reverse-engineered from `leftovers/macos.rs` 0x10079c020)
# ---------------------------------------------------------------------------

def collect_installed_bundle_ids(app_dirs: Optional[List[str]] = None) -> set[str]:
    if app_dirs is None:
        app_dirs = [
            "/Applications",
            "/System/Applications",
            str(Path.home() / "Applications"),
            "/Volumes/databox/Applications",
        ]
    bundle_ids = set()
    for d in app_dirs:
        if not os.path.isdir(d):
            continue
        try:
            with os.scandir(d) as it:
                for entry in it:
                    if entry.name.endswith(".app"):
                        plist_p = os.path.join(entry.path, "Contents", "Info.plist")
                        if os.path.isfile(plist_p):
                            try:
                                with open(plist_p, "rb") as f:
                                    pl = plistlib.load(f)
                                bid = pl.get("CFBundleIdentifier")
                                if bid:
                                    bundle_ids.add(bid)
                            except Exception:
                                pass
        except OSError:
            continue
    return bundle_ids


def scan_container_leftovers(
    containers_root: Optional[str] = None,
    installed_bundle_ids: Optional[set[str]] = None,
) -> List[Dict[str, Any]]:
    if containers_root is None:
        containers_root = str(Path.home() / "Library" / "Containers")
    if not os.path.isdir(containers_root):
        return []
    if installed_bundle_ids is None:
        installed_bundle_ids = collect_installed_bundle_ids()

    leftovers = []
    try:
        with os.scandir(containers_root) as it:
            for entry in it:
                if not entry.is_dir(follow_symlinks=False):
                    continue
                meta_plist = os.path.join(entry.path, ".com.apple.containermanagerd.metadata.plist")
                if not os.path.isfile(meta_plist):
                    continue
                try:
                    with open(meta_plist, "rb") as f:
                        pl = plistlib.load(f)
                    ident = pl.get("MCMMetadataIdentifier") or entry.name
                    if ident.startswith("com.apple."):
                        continue
                    info = pl.get("MCMMetadataInfo", {})
                    params = (
                        info.get("SandboxProfileDataValidationInfo", {})
                        .get("SandboxProfileDataValidationInfoParameters", {})
                    )
                    app_bundle_id = params.get("application_bundle_id") or ident
                    former_bundle_path = params.get("application_bundle")

                    if app_bundle_id in installed_bundle_ids:
                        continue
                    if former_bundle_path and os.path.exists(former_bundle_path):
                        continue
                    if not former_bundle_path:
                        continue

                    sz, cnt, trunc = measure_directory_fast(entry.path, budget_seconds=0.6)
                    if sz > 1024 * 1024:
                        leftovers.append({
                            "container_id": ident,
                            "application_bundle_id": app_bundle_id,
                            "former_bundle_path": former_bundle_path,
                            "container_path": entry.path,
                            "allocated_bytes": sz,
                            "file_count": cnt,
                            "truncated": trunc,
                        })
                except Exception:
                    continue
    except OSError:
        pass

    leftovers.sort(key=lambda x: x["allocated_bytes"], reverse=True)
    return leftovers


# ---------------------------------------------------------------------------
# 7. Transactional Universal Binary Inspector & Thinner (MangoDisk 0x1009372c0)
# ---------------------------------------------------------------------------

def scan_universal_binaries(apps_dir: str = "/Applications") -> List[Dict[str, Any]]:
    results = []
    if not os.path.isdir(apps_dir):
        return results
    try:
        entries = sorted(os.scandir(apps_dir), key=lambda e: e.name)
    except OSError:
        return results

    for entry in entries:
        if not entry.name.endswith(".app") or entry.is_symlink():
            continue
        plist_p = os.path.join(entry.path, "Contents", "Info.plist")
        if not os.path.isfile(plist_p):
            continue
        try:
            with open(plist_p, "rb") as f:
                pl = plistlib.load(f)
            exe_name = pl.get("CFBundleExecutable")
            if not exe_name:
                continue
            exe_path = os.path.join(entry.path, "Contents", "MacOS", exe_name)
            if not os.path.isfile(exe_path) or os.path.islink(exe_path):
                continue
            out = subprocess.check_output(
                ["/usr/bin/lipo", "-detailed_info", exe_path],
                text=True,
                stderr=subprocess.DEVNULL,
                timeout=3.0,
            )
            if "architecture x86_64" in out and "architecture arm64" in out:
                x86_size = 0
                in_x86 = False
                for line in out.splitlines():
                    if "architecture x86_64" in line:
                        in_x86 = True
                    elif "architecture " in line:
                        in_x86 = False
                    elif in_x86 and "size " in line:
                        parts = line.strip().split()
                        if len(parts) >= 2 and parts[1].isdigit():
                            x86_size = int(parts[1])
                if x86_size > 1024 * 1024:
                    results.append({
                        "app_name": entry.name,
                        "bundle_path": entry.path,
                        "executable_path": exe_path,
                        "total_size": os.path.getsize(exe_path),
                        "x86_64_slice_bytes": x86_size,
                    })
        except Exception:
            continue

    results.sort(key=lambda x: x["x86_64_slice_bytes"], reverse=True)
    return results


def thin_universal_binary_transactional(bundle_path: str, executable_path: str, dry_run: bool = True) -> Dict[str, Any]:
    """
    Reverse-engineered from MangoDisk `macos_universal_binaries::platform::execute` (0x1009372c0):
    1. Creates an APFS CoW backup using `/bin/cp -c` (`fclonefileat`).
    2. Runs `/usr/bin/lipo -thin arm64`.
    3. Runs `/usr/bin/codesign --verify --deep --strict <bundle_path>` (0x10093baa8).
    4. Runs `/usr/sbin/spctl --assess --type execute <bundle_path>` (0x10093be6c).
    5. Rolls back automatically if either verification fails!
    """
    if dry_run:
        return {"status": "dry_run", "bundle_path": bundle_path, "executable_path": executable_path}

    backup_path = executable_path + ".mangodisk-cow-backup"
    try:
        subprocess.run(["/bin/cp", "-c", executable_path, backup_path], check=True)
    except subprocess.CalledProcessError:
        shutil.copy2(executable_path, backup_path)

    thin_tmp = executable_path + ".arm64-thin"
    try:
        subprocess.run(["/usr/bin/lipo", executable_path, "-thin", "arm64", "-output", thin_tmp], check=True)
        shutil.copymode(executable_path, thin_tmp)
        os.replace(thin_tmp, executable_path)

        cs = subprocess.run(
            ["/usr/bin/codesign", "--verify", "--deep", "--strict", bundle_path],
            capture_output=True,
            text=True,
        )
        sp = subprocess.run(
            ["/usr/sbin/spctl", "--assess", "--type", "execute", bundle_path],
            capture_output=True,
            text=True,
        )
        if cs.returncode != 0 or sp.returncode != 0:
            os.replace(backup_path, executable_path)
            return {
                "status": "rolled_back",
                "reason": "codesign_or_gatekeeper_rejected_thin_slice",
                "codesign_rc": cs.returncode,
                "spctl_rc": sp.returncode,
            }
        os.unlink(backup_path)
        return {"status": "thinned_and_verified", "bundle_path": bundle_path}
    except Exception as exc:
        if os.path.exists(thin_tmp):
            os.unlink(thin_tmp)
        if os.path.exists(backup_path):
            os.replace(backup_path, executable_path)
        return {"status": "rolled_back", "reason": str(exc)}


# ---------------------------------------------------------------------------
# 8. Cold-Tier Archive & Relocate Engine (/Volumes/archive Safety-Net Backstop)
# ---------------------------------------------------------------------------

def inspect_tree_for_archive(path_str: str, budget_seconds: float = 2.0) -> Tuple[int, int, int]:
    """
    Returns `(allocated_bytes, non_appledouble_files, internal_symlinks)` for a file or directory.
    """
    if not os.path.lexists(path_str) or os.path.islink(path_str):
        return 0, 0, 0
    try:
        st = os.stat(path_str, follow_symlinks=False)
    except OSError:
        return 0, 0, 0

    if os.path.isfile(path_str):
        return st.st_blocks * 512, 1, 0

    t0 = time.monotonic()
    total_bytes = 0
    file_count = 0
    symlink_count = 0
    stack = [path_str]
    while stack:
        if (time.monotonic() - t0) > budget_seconds:
            break
        curr = stack.pop()
        try:
            with os.scandir(curr) as it:
                for entry in it:
                    if entry.name.startswith("._") or entry.name in NETWORK_DIR_BLACKLIST:
                        continue
                    try:
                        if entry.is_symlink():
                            symlink_count += 1
                        elif entry.is_dir(follow_symlinks=False):
                            stack.append(entry.path)
                        elif entry.is_file(follow_symlinks=False):
                            est = entry.stat(follow_symlinks=False)
                            total_bytes += est.st_blocks * 512
                            file_count += 1
                    except OSError:
                        continue
        except OSError:
            continue
    return total_bytes, file_count, symlink_count


def is_archive_destination_ready(dest_root: str) -> bool:
    """
    Ensures that if `dest_root` is under `/Volumes/<disk>`, `<disk>` is an actively
    mounted local filesystem (`os.path.ismount`), preventing writes to an unmounted
    `/Volumes/<disk>` stub directory on the root disk.
    """
    abs_dest = os.path.abspath(dest_root)
    if abs_dest.startswith("/Volumes/"):
        parts = abs_dest.split("/")
        if len(parts) >= 3 and parts[2]:
            mount_pt = f"/Volumes/{parts[2]}"
            if not os.path.ismount(mount_pt) or not is_local_filesystem(mount_pt):
                return False
            return True
    check_target = abs_dest
    while not os.path.exists(check_target) and check_target != "/":
        check_target = os.path.dirname(check_target)
    return is_local_filesystem(check_target)


def scan_archive_candidates(
    rules: Optional[List[Dict[str, Any]]] = None,
    archive_vault_root: str = ARCHIVE_VAULT_ROOT,
    databox_fallback_root: str = DATABOX_ARCHIVE_FALLBACK,
) -> List[ArchiveCandidate]:
    """
    Scans cold directories and installer files that can be safely relocated to
    `/Volumes/archive` (or `/Volumes/databox` if internal POSIX symlinks exist and archive is ExFAT).
    """
    active_rules = rules if rules is not None else ARCHIVE_RULES
    now = time.time()
    candidates: List[ArchiveCandidate] = []
    archive_ready = is_archive_destination_ready(archive_vault_root)
    databox_ready = is_archive_destination_ready(databox_fallback_root)
    archive_fs = get_filesystem_info(archive_vault_root) if archive_ready else None
    archive_is_exfat = bool(archive_fs and archive_fs[0] in ("exfat", "msdos", "fat32"))

    def evaluate_item(rule: Dict[str, Any], src_path: str) -> None:
        expanded = os.path.expanduser(src_path)
        if not os.path.lexists(expanded) or os.path.islink(expanded):
            return
        if not is_safe_to_modify(expanded, allow_external_volumes=True):
            return
        try:
            st = os.stat(expanded, follow_symlinks=False)
        except OSError:
            return
        age_days = (now - st.st_mtime) / 86400.0
        if age_days < rule.get("min_age_days", 0):
            return
        sz, fcnt, sym_cnt = inspect_tree_for_archive(expanded, budget_seconds=12.0)
        if sz <= 0 or fcnt <= 0:
            return

        explicit_target_root = rule.get("target_root")
        if explicit_target_root:
            if not is_archive_destination_ready(explicit_target_root):
                return
            base_dest = explicit_target_root
            dest_vol = resolve_volume_for_path(explicit_target_root)
        elif archive_is_exfat and (sym_cnt > 0 or fcnt > 500):
            if not databox_ready:
                return
            base_dest = databox_fallback_root
            dest_vol = resolve_volume_for_path(databox_fallback_root)
        else:
            if not archive_ready:
                return
            base_dest = archive_vault_root
            dest_vol = resolve_volume_for_path(archive_vault_root)

        dest_path = os.path.join(base_dest, rule["dest_subdir"], os.path.basename(expanded))
        src_vol = resolve_volume_for_path(expanded)
        if src_vol == dest_vol and os.path.abspath(expanded).startswith(os.path.abspath(base_dest)):
            return

        candidates.append(
            ArchiveCandidate(
                rule_id=rule["id"],
                op=rule["op"],
                description=rule["description"],
                source_path=expanded,
                source_volume=src_vol,
                dest_path=dest_path,
                dest_volume=dest_vol,
                allocated_bytes=sz,
                file_count=fcnt,
                internal_symlinks=sym_cnt,
                age_days=round(age_days, 1),
            )
        )

    installer_exts = (".dmg", ".pkg", ".apk", ".iso")
    for rule in active_rules:
        for s in rule.get("sources", []):
            evaluate_item(rule, s)
        children_parent = rule.get("scan_children_of")
        if children_parent:
            parent_exp = os.path.expanduser(children_parent)
            include_files = bool(rule.get("include_child_files", False))
            if os.path.isdir(parent_exp) and is_local_filesystem(os.path.realpath(parent_exp)):
                try:
                    for entry in sorted(os.scandir(parent_exp), key=lambda e: e.name):
                        if entry.name.startswith("."):
                            continue
                        if entry.is_dir(follow_symlinks=False) or (include_files and entry.is_file(follow_symlinks=False)):
                            evaluate_item(rule, entry.path)
                except OSError:
                    pass
        installers_dir = rule.get("scan_installers_in")
        if installers_dir:
            dl_exp = os.path.expanduser(installers_dir)
            if os.path.isdir(dl_exp) and not os.path.islink(dl_exp):
                try:
                    for entry in sorted(os.scandir(dl_exp), key=lambda e: e.name):
                        if (
                            not entry.name.startswith(".")
                            and entry.is_file(follow_symlinks=False)
                            and entry.name.lower().endswith(installer_exts)
                        ):
                            try:
                                if entry.stat(follow_symlinks=False).st_size >= 20 * 1024 * 1024:
                                    evaluate_item(rule, entry.path)
                            except OSError:
                                pass
                except OSError:
                    pass

    candidates.sort(key=lambda c: c.allocated_bytes, reverse=True)
    return candidates


def execute_archive_migration(
    candidates: List[ArchiveCandidate],
    dry_run: bool = True,
    manifest_dir: str = ARCHIVE_MANIFEST_DIR,
) -> Dict[str, Any]:
    """
    Executes verified Cold-Tier Archive migrations (`move+symlink` or `move_cold`):
    1. Verifies target volume is mounted (`is_archive_destination_ready`).
    2. Resolves collision-free destination path if `dest_path` already exists.
    3. Copies source to destination via `rsync` (or `shutil.copy2` for single files).
    4. Verifies non-AppleDouble file count parity before deleting the source.
    5. For `move+symlink`, atomically creates a symlink at `source_path -> actual_dest`.
    6. Writes an audit manifest JSON in `manifest_dir`.
    """
    actions_log: List[Dict[str, Any]] = []
    total_migrated_bytes = 0
    by_source_vol: Dict[str, int] = {}

    manifest_path: Optional[str] = None
    try:
        for c in candidates:
            if not os.path.lexists(c.source_path) or os.path.islink(c.source_path):
                continue
            if not is_safe_to_modify(c.source_path, allow_external_volumes=True):
                continue
            if not is_archive_destination_ready(c.dest_path):
                continue

            actual_dest = c.dest_path
            if os.path.lexists(actual_dest):
                stamp = time.strftime("%Y%m%d_%H%M%S")
                if os.path.isfile(c.source_path):
                    base, ext = os.path.splitext(actual_dest)
                    actual_dest = f"{base}_{stamp}{ext}" if ext else f"{actual_dest}_{stamp}"
                else:
                    actual_dest = f"{actual_dest}_{stamp}"

            if dry_run:
                total_migrated_bytes += c.allocated_bytes
                by_source_vol[c.source_volume] = by_source_vol.get(c.source_volume, 0) + c.allocated_bytes
                actions_log.append({
                    "status": "dry_run",
                    "rule_id": c.rule_id,
                    "op": c.op,
                    "src": c.source_path,
                    "dest": actual_dest,
                    "bytes": c.allocated_bytes,
                    "files": c.file_count,
                    "internal_symlinks": c.internal_symlinks,
                })
                continue

            os.makedirs(os.path.dirname(actual_dest), exist_ok=True)
            src_is_file = os.path.isfile(c.source_path)
            _, src_files, src_syms = inspect_tree_for_archive(c.source_path, budget_seconds=180.0)

            if src_is_file:
                shutil.copy2(c.source_path, actual_dest)
            else:
                os.makedirs(actual_dest, exist_ok=True)
                dest_fs = get_filesystem_info(os.path.dirname(actual_dest))
                dest_is_exfat = bool(dest_fs and dest_fs[0] in ("exfat", "msdos", "fat32"))
                rsync_flags = "-rltD" if dest_is_exfat else "-a"
                subprocess.run(
                    [
                        "/usr/bin/rsync",
                        rsync_flags,
                        "--exclude=._*",
                        c.source_path.rstrip("/") + "/",
                        actual_dest.rstrip("/") + "/",
                    ],
                    check=True,
                )

            # Strict verification gate before source removal
            _, dest_files, _ = inspect_tree_for_archive(actual_dest, budget_seconds=180.0)
            if dest_files < src_files:
                raise RuntimeError(
                    f"Archive parity check failed for {c.source_path} -> {actual_dest}: "
                    f"src_files={src_files}, dest_files={dest_files}"
                )

            if src_is_file:
                try:
                    os.unlink(c.source_path)
                except PermissionError:
                    os.chmod(os.path.dirname(c.source_path), 0o755)
                    os.chmod(c.source_path, 0o644)
                    os.unlink(c.source_path)
            else:
                try:
                    shutil.rmtree(c.source_path)
                except PermissionError:
                    subprocess.run(["/bin/chmod", "-R", "u+w", c.source_path], check=False)
                    shutil.rmtree(c.source_path)

            if c.op == "move+symlink":
                os.symlink(actual_dest, c.source_path)

            total_migrated_bytes += c.allocated_bytes
            by_source_vol[c.source_volume] = by_source_vol.get(c.source_volume, 0) + c.allocated_bytes
            actions_log.append({
                "status": "archived",
                "rule_id": c.rule_id,
                "op": c.op,
                "src": c.source_path,
                "dest": actual_dest,
                "bytes": c.allocated_bytes,
                "files": src_files,
                "verified_dest_files": dest_files,
                "internal_symlinks": src_syms,
                "symlink_created": c.op == "move+symlink",
            })
    finally:
        if not dry_run and actions_log and is_archive_destination_ready(manifest_dir):
            os.makedirs(manifest_dir, exist_ok=True)
            ts = time.strftime("%Y-%m-%d_%H%M%S")
            manifest_path = os.path.join(manifest_dir, f"curator_archive_{ts}.json")
            with open(manifest_path, "w", encoding="utf-8") as f:
                json.dump(
                    {
                        "schema": "mac-tiered-curator-archive-v1",
                        "timestamp": ts,
                        "total_bytes": total_migrated_bytes,
                        "total_human": format_bytes(total_migrated_bytes),
                        "by_source_volume": {k: format_bytes(v) for k, v in by_source_vol.items()},
                        "actions": actions_log,
                    },
                    f,
                    indent=2,
                    ensure_ascii=False,
                )

    return {
        "dry_run": dry_run,
        "total_bytes": total_migrated_bytes,
        "total_human": format_bytes(total_migrated_bytes),
        "by_source_volume": {k: format_bytes(v) for k, v in by_source_vol.items()},
        "manifest_path": manifest_path,
        "actions": actions_log,
    }


def prune_bundle_migrations(
    caches_root: Optional[str] = None,
    keep_backups: int = 2,
    min_work_age_days: int = 7,
    dry_run: bool = True,
) -> Dict[str, Any]:
    """
    Rotates `~/Library/Caches/*.BundleMigration`:
    - Cleans `downloads/` and `extracted/` children older than `min_work_age_days`.
    - Retains the newest `keep_backups` `*.backup.app` bundles in `backups/` and prunes older ones.
    """
    root_dir = os.path.expanduser(caches_root or "~/Library/Caches")
    freed_bytes = 0
    removed_items: List[str] = []
    if not os.path.isdir(root_dir) or not is_local_filesystem(root_dir):
        return {"dry_run": dry_run, "freed_bytes": 0, "removed_items": []}

    now = time.time()
    try:
        bm_dirs = [
            e.path for e in os.scandir(root_dir)
            if e.name.endswith(".BundleMigration") and e.is_dir(follow_symlinks=True)
        ]
    except OSError:
        return {"dry_run": dry_run, "freed_bytes": 0, "removed_items": []}

    for bm in bm_dirs:
        for sub in ("downloads", "extracted"):
            sub_dir = os.path.join(bm, sub)
            if not os.path.isdir(sub_dir):
                continue
            try:
                for entry in os.scandir(sub_dir):
                    try:
                        st = entry.stat(follow_symlinks=False)
                    except OSError:
                        continue
                    if (now - st.st_mtime) / 86400.0 >= min_work_age_days:
                        sz, _, _ = measure_directory_fast(entry.path, budget_seconds=1.0)
                        if not dry_run:
                            if entry.is_dir(follow_symlinks=False):
                                shutil.rmtree(entry.path, ignore_errors=True)
                            else:
                                try:
                                    os.unlink(entry.path)
                                except OSError:
                                    pass
                        freed_bytes += sz
                        removed_items.append(entry.path)
            except OSError:
                continue

        backups_dir = os.path.join(bm, "backups")
        if os.path.isdir(backups_dir):
            backups: List[Tuple[float, str]] = []
            try:
                for entry in os.scandir(backups_dir):
                    if entry.name.endswith(".backup.app"):
                        try:
                            backups.append((entry.stat(follow_symlinks=False).st_mtime, entry.path))
                        except OSError:
                            continue
            except OSError:
                pass
            backups.sort(key=lambda x: x[0], reverse=True)
            for _, old_backup_path in backups[keep_backups:]:
                sz, _, _ = measure_directory_fast(old_backup_path, budget_seconds=1.5)
                if not dry_run:
                    shutil.rmtree(old_backup_path, ignore_errors=True)
                freed_bytes += sz
                removed_items.append(old_backup_path)

    return {
        "dry_run": dry_run,
        "freed_bytes": freed_bytes,
        "freed_human": format_bytes(freed_bytes),
        "removed_items": removed_items,
    }


def prune_cursor_and_updater_versions(
    agent_cli_root: Optional[str] = None,
    cursor_runtime_root: Optional[str] = None,
    keep_versions: int = 2,
    dry_run: bool = True,
) -> Dict[str, Any]:
    """
    Performs N-keep-K rotation on versioned runtime directories:
    1. Cursor `agent-cli` versions (`~/.local/share/cursor-agent/versions` under Cursor globalStorage):
       - Inspects `.local/bin/cursor-agent` symlink to pin the currently active version directory.
       - Keeps the newest `keep_versions` directories by mtime PLUS any symlink-pinned version, pruning older versions.
    2. Cursor runtime `CachedData` and `logs` on `/Volumes/Cache/app/cursor-runtime`:
       - Keeps the newest `keep_versions` commit/session subdirectories so running Cursor sessions remain untouched,
         pruning older historical subdirectories.
    """
    base_agent_cli = os.path.expanduser(
        agent_cli_root
        or "~/Library/Application Support/Cursor/User/globalStorage/anysphere.cursor-agent-worker/agent-cli"
    )
    base_runtime = os.path.expanduser(
        cursor_runtime_root or "/Volumes/Cache/app/cursor-runtime"
    )
    freed_bytes = 0
    removed_items: List[str] = []
    pinned_versions: set[str] = set()

    bin_link = os.path.join(base_agent_cli, ".local", "bin", "cursor-agent")
    if os.path.islink(bin_link):
        try:
            target = os.readlink(bin_link)
            if not os.path.isabs(target):
                target = os.path.normpath(os.path.join(os.path.dirname(bin_link), target))
            pinned_versions.add(os.path.basename(os.path.dirname(target)))
        except OSError:
            pass

    def _rotate_subdirs(parent_dir: str, pinned_names: Optional[set[str]] = None) -> None:
        nonlocal freed_bytes
        if not os.path.isdir(parent_dir) or not is_local_filesystem(parent_dir):
            return
        entries: List[Tuple[float, str, str]] = []
        try:
            for entry in os.scandir(parent_dir):
                if entry.name.startswith(".") or not entry.is_dir(follow_symlinks=False):
                    continue
                try:
                    entries.append((entry.stat(follow_symlinks=False).st_mtime, entry.name, entry.path))
                except OSError:
                    continue
        except OSError:
            return
        entries.sort(key=lambda x: x[0], reverse=True)
        for _, name, path in entries[keep_versions:]:
            if pinned_names and name in pinned_names:
                continue
            if not is_safe_to_modify(path, allow_external_volumes=True):
                continue
            sz, _, _ = measure_directory_fast(path, budget_seconds=1.5)
            if not dry_run:
                shutil.rmtree(path, ignore_errors=True)
            freed_bytes += sz
            removed_items.append(path)

    versions_dir = os.path.join(base_agent_cli, ".local", "share", "cursor-agent", "versions")
    _rotate_subdirs(versions_dir, pinned_names=pinned_versions)

    for sub in ("CachedData", "logs"):
        _rotate_subdirs(os.path.join(base_runtime, sub))

    return {
        "dry_run": dry_run,
        "freed_bytes": freed_bytes,
        "freed_human": format_bytes(freed_bytes),
        "pinned_versions": sorted(pinned_versions),
        "removed_items": removed_items,
    }


def prune_playwright_browser_versions(
    playwright_root: Optional[str] = None,
    keep_versions: int = 1,
    dry_run: bool = True,
) -> Dict[str, Any]:
    """
    Performs N-keep-K rotation on cached Playwright browser downloads:
    - Scans ~/Library/Caches/ms-playwright (following symlinks to /Volumes/Cache)
    - Groups versioned directories by family (e.g. 'chromium-', 'chromium_headless_shell-')
    - Retains the newest `keep_versions` per family by mtime/version and prunes older historical versions.
    """
    base = os.path.realpath(os.path.expanduser(playwright_root or "~/Library/Caches/ms-playwright"))
    freed_bytes = 0
    removed_items: List[str] = []

    if os.path.isdir(base) and is_local_filesystem(base):
        families: Dict[str, List[Tuple[float, str, str]]] = collections.defaultdict(list)
        try:
            for entry in os.scandir(base):
                if entry.name.startswith(".") or not entry.is_dir(follow_symlinks=False):
                    continue
                if "-" in entry.name:
                    family, ver_str = entry.name.rsplit("-", 1)
                    if ver_str.isdigit():
                        try:
                            st = entry.stat(follow_symlinks=False)
                            families[family].append((st.st_mtime, entry.name, entry.path))
                        except OSError:
                            pass

            for family, items in families.items():
                items.sort(key=lambda x: x[0], reverse=True)
                for mtime, name, path in items[keep_versions:]:
                    if not is_safe_to_modify(path, allow_external_volumes=True):
                        continue
                    sz, _, _ = measure_directory_fast(path, budget_seconds=1.5)
                    freed_bytes += sz
                    removed_items.append(path)
                    if not dry_run:
                        shutil.rmtree(path, ignore_errors=True)
        except OSError:
            pass

    return {
        "dry_run": dry_run,
        "freed_bytes": freed_bytes,
        "freed_human": format_bytes(freed_bytes),
        "removed_items": removed_items,
    }


def run_periodic_routine(
    apply: bool = False,
    min_reclaim_mb: float = 10.0,
) -> Dict[str, Any]:
    """
    Executes the 5-phase periodic maintenance pipeline in a single idempotent run:
    1. Pre-flight 4-tier volume watermark check
    2. Multi-hop broken symlink auto-healing (never removes orphans automatically)
    3. Safe symlink-preserving cache & residue cleanup + BundleMigration & Cursor version rotation
    4. Lossless AI Agent SQLite compaction (`VACUUM` when freelist >= `min_reclaim_mb`)
    5. Cold-tier archive & relocate (`archive --rules all`) with parity check & manifest
    """
    dry_run = not apply
    ts = time.strftime("%Y-%m-%dT%H:%M:%S%z")
    volumes_before = [dataclasses.asdict(v) for v in inspect_volumes()]

    # Phase 2: Symlink Auto-Healing
    broken_records = scan_broken_symlinks()
    symlink_stats = repair_or_remove_broken_symlinks(
        broken_records, remove_orphans=False, dry_run=dry_run
    )

    # Phase 3: Safe Cache Cleanup + BundleMigration & Cursor Version Rotation
    routine_rule_ids = {
        r["id"] for r in CLEANUP_RULES if r["default_selected"] and r["risk"] == "safe"
    }
    routine_rule_ids.update({
        "dev.appledouble-metadata",
        "agent.stale-logs-and-Update-Staging",
    })
    cleanup_cands = scan_cleanup_candidates(budget_per_path=1.5)
    cleaned_actions: List[Dict[str, Any]] = []
    total_cleaned_bytes = 0
    for c in cleanup_cands:
        if c.rule_id in routine_rule_ids:
            freed, cnt = clean_directory_contents_preserving_root(c.logical_path, dry_run=dry_run)
            total_cleaned_bytes += freed
            if freed > 0 or cnt > 0:
                cleaned_actions.append({
                    "rule_id": c.rule_id,
                    "logical_path": c.logical_path,
                    "physical_volume": c.physical_volume,
                    "freed_bytes": freed,
                    "freed_human": format_bytes(freed),
                    "items": cnt,
                })

    bm_res = prune_bundle_migrations(dry_run=dry_run)
    total_cleaned_bytes += bm_res["freed_bytes"]

    cursor_rot_res = prune_cursor_and_updater_versions(dry_run=dry_run)
    total_cleaned_bytes += cursor_rot_res["freed_bytes"]

    pw_rot_res = prune_playwright_browser_versions(dry_run=dry_run)
    total_cleaned_bytes += pw_rot_res["freed_bytes"]

    # Phase 4: Lossless SQLite Compaction
    sqlite_dbs = analyze_sqlite_databases()
    threshold_bytes = int(min_reclaim_mb * 1024 * 1024)
    sqlite_actions: List[Dict[str, Any]] = []
    total_sqlite_saved = 0
    for db in sqlite_dbs:
        if db.get("reclaimable_bytes", 0) >= threshold_bytes:
            res = vacuum_sqlite_database_safe(db["path"], dry_run=dry_run)
            saved = res.get("saved_bytes", db.get("reclaimable_bytes", 0) if dry_run else 0)
            total_sqlite_saved += saved
            sqlite_actions.append(res)

    # Phase 5: Cold-Tier Archive & Relocate
    archive_cands = scan_archive_candidates()
    archive_res = execute_archive_migration(archive_cands, dry_run=dry_run)

    volumes_after = [dataclasses.asdict(v) for v in inspect_volumes(auto_heal_cloud=apply)]

    summary = {
        "schema": "mac-tiered-curator-routine-v1",
        "timestamp": ts,
        "dry_run": dry_run,
        "volumes_before": volumes_before,
        "volumes_after": volumes_after,
        "symlinks": symlink_stats,
        "cleanup": {
            "total_freed_bytes": total_cleaned_bytes,
            "total_freed_human": format_bytes(total_cleaned_bytes),
            "bundle_migration": bm_res,
            "cursor_version_rotation": cursor_rot_res,
            "playwright_version_rotation": pw_rot_res,
            "actions": cleaned_actions,
        },
        "sqlite_vacuum": {
            "total_saved_bytes": total_sqlite_saved,
            "total_saved_human": format_bytes(total_sqlite_saved),
            "actions": sqlite_actions,
        },
        "archive": archive_res,
    }

    if apply:
        log_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "logs")
        try:
            os.makedirs(log_dir, exist_ok=True)
            latest_path = os.path.join(log_dir, "routine_latest.json")
            with open(latest_path, "w", encoding="utf-8") as f:
                json.dump(summary, f, indent=2, ensure_ascii=False)
            summary["routine_log_path"] = latest_path
        except OSError:
            pass

    return summary


# ---------------------------------------------------------------------------
# auto-safe: move+symlink cold archive and local symlink rewrite only
# ---------------------------------------------------------------------------

HERMES_EXCLUDED_ARCHIVE_IDS = frozenset({
    "archive.hermes-checkpoints",
    "archive.hermes-cold-work",
    "archive.cache-older-hermes-backups",
    "archive.hermes-corrupt-db-snapshots",
})

AUTO_SAFE_ARCHIVE_IDS = frozenset({
    "archive.cache-iso-staging",
    "archive.cache-cold-unity",
    "archive.cache-cold-ml",
    "archive.home-cold-workspaces",
    "archive.dot-cache-codex-runtimes",
    "archive.openclaw-sealed-copies",
    "archive.codex-retired-dirs",
    "archive.home-root-node-modules",
    "archive.workbuddy-cold-sessions",
})

STATIC_AUTO_SAFE_HOLDS = (
    {"id": "vacuum-sqlite", "kind": "maintenance", "reason": "不可恢复删除", "detail": "不执行 VACUUM，不打开 ~/.hermes", "bytes": None},
    {"id": "uv-cache-prune", "kind": "maintenance", "reason": "不可恢复删除", "detail": "不执行 uv cache prune", "bytes": None},
    {"id": "prune_bundle_migrations", "kind": "maintenance", "reason": "不可恢复删除", "detail": "不执行版本目录 rmtree", "bytes": None},
    {"id": "prune_cursor_and_updater_versions", "kind": "maintenance", "reason": "不可恢复删除", "detail": "不执行版本目录 rmtree", "bytes": None},
    {"id": "l0.archive_workbuddy_logs", "kind": "l0", "reason": "不可恢复删除", "detail": "原 l0_hygiene 步骤已停用", "bytes": None},
    {"id": "l0.archive_workbuddy_sandbox_logs", "kind": "l0", "reason": "不可恢复删除", "detail": "原 l0_hygiene 步骤已停用", "bytes": None},
    {"id": "l0.archive_workbuddy_traces", "kind": "l0", "reason": "不可恢复删除", "detail": "原 l0_hygiene 步骤已停用", "bytes": None},
    {"id": "l0.archive_openclaw_backups", "kind": "l0", "reason": "不可恢复删除", "detail": "原 l0_hygiene 步骤已停用", "bytes": None},
    {"id": "l0.cleanup_openclaw_tmp", "kind": "l0", "reason": "不可恢复删除", "detail": "原 l0_hygiene 步骤已停用", "bytes": None},
    {"id": "l0.archive_stale_user_tmp_downloads", "kind": "l0", "reason": "不可恢复删除", "detail": "原 l0_hygiene 步骤已停用", "bytes": None},
    {"id": "l0.prune_l0_logs", "kind": "l0", "reason": "不可恢复删除", "detail": "原 l0_hygiene 步骤已停用", "bytes": None},
    {"id": "l0.purge_update_residue", "kind": "l0", "reason": "不可恢复删除", "detail": "原 l0_hygiene 步骤已停用", "bytes": None},
    {"id": "l0.prune_bundle_migration", "kind": "l0", "reason": "不可恢复删除", "detail": "原 l0_hygiene 步骤已停用", "bytes": None},
    {"id": "clean.safe_defaults", "kind": "maintenance", "reason": "不可恢复删除", "detail": "不执行 clean --rules safe_defaults", "bytes": None},
)


class AutoSafeRefuse(Exception):
    def __init__(self, reason: str, incomplete_path: Optional[str] = None):
        super().__init__(reason)
        self.reason = reason
        self.incomplete_path = incomplete_path


def _hold(item_id: str, kind: str, reason: str, detail: str, byte_count: Optional[int] = None) -> Dict[str, Any]:
    return {
        "id": item_id,
        "kind": kind,
        "reason": reason,
        "detail": detail,
        "bytes": byte_count,
    }


def _hold_from_block(item_id: str, kind: str, code: str) -> Dict[str, Any]:
    if code == "hermes":
        return _hold(item_id, kind, "已排除", "不打开 ~/.hermes")
    if code == "volume_not_mounted":
        return _hold(item_id, kind, "目标卷未挂载", code)
    return _hold(item_id, kind, "落入禁止集", code)


def _rule_paths(rule: Dict[str, Any]) -> List[str]:
    paths = list(rule.get("sources") or [])
    if rule.get("scan_children_of"):
        paths.append(rule["scan_children_of"])
    if rule.get("scan_installers_in"):
        paths.append(rule["scan_installers_in"])
    return paths


def auto_safe_block_reason(path_str: str) -> Optional[str]:
    """Forbidden-set check. Prefix hits return before any directory listing."""
    if not path_str:
        return "empty_path"
    prefix = _auto_safe_prefix_block(path_str)
    if prefix:
        return prefix
    raw = os.path.normpath(os.path.abspath(os.path.expanduser(path_str)))
    if raw.startswith("/Volumes/"):
        parts = raw.split("/")
        if len(parts) >= 3 and parts[2] and raw != f"/Volumes/{parts[2]}":
            mount = f"/Volumes/{parts[2]}"
            if not os.path.ismount(mount):
                return "volume_not_mounted"
    probe = raw if os.path.exists(raw) else os.path.dirname(raw)
    if os.path.lexists(raw) and not os.path.islink(raw):
        real = os.path.normpath(os.path.realpath(raw))
        prefix = _auto_safe_prefix_block(real)
        if prefix:
            return prefix
        probe = real
    elif os.path.islink(raw):
        link_target = os.readlink(raw)
        abs_target = link_target if os.path.isabs(link_target) else os.path.normpath(os.path.join(os.path.dirname(raw), link_target))
        prefix = _auto_safe_prefix_block(abs_target)
        if prefix:
            return prefix
        probe = os.path.dirname(raw)
    prefix = _auto_safe_prefix_block(probe)
    if prefix:
        return prefix
    info = get_filesystem_info(probe if os.path.exists(probe) else os.path.dirname(probe))
    if info is None:
        return "filesystem_unknown"
    fstype, is_local, mnt = info
    if (not is_local) or fstype in NETWORK_FSTYPES:
        return "network_volume"
    if mnt:
        mounted = _auto_safe_prefix_block(os.path.normpath(mnt))
        if mounted:
            return mounted
    return None


def partition_auto_safe_rules(
    rules: List[Dict[str, Any]],
    allow_ids: Optional[set] = None,
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """Split archive rules into move+symlink work and weekly-hold rows. Does not scan."""
    allowed_ids = AUTO_SAFE_ARCHIVE_IDS if allow_ids is None else set(allow_ids)
    allowed: List[Dict[str, Any]] = []
    holds: List[Dict[str, Any]] = []
    for rule in rules:
        rule_id = rule["id"]
        paths = _rule_paths(rule)
        if rule_id in HERMES_EXCLUDED_ARCHIVE_IDS or any(_auto_safe_prefix_block(p) == "hermes" for p in paths):
            holds.append(_hold(rule_id, "archive_rule", "已排除", "不打开 ~/.hermes"))
            continue
        blocked = next((_auto_safe_prefix_block(p) for p in paths if _auto_safe_prefix_block(p)), None)
        if blocked:
            holds.append(_hold_from_block(rule_id, "archive_rule", blocked))
            continue
        if rule.get("op") != "move+symlink" or rule_id not in allowed_ids:
            holds.append(_hold(rule_id, "archive_rule", "不可恢复删除", str(rule.get("op") or "not_allowlisted")))
            continue
        allowed.append(rule)
    return allowed, holds


def exact_tree_stats(path_str: str) -> Tuple[int, int, int]:
    """Logical byte count, regular file count, and internal symlink count."""
    reason = auto_safe_block_reason(path_str)
    if reason:
        raise AutoSafeRefuse(reason)
    if (not os.path.lexists(path_str)) or os.path.islink(path_str):
        raise AutoSafeRefuse("source_missing_or_link")
    root_info = get_filesystem_info(path_str)
    if root_info is None or (not root_info[1]) or root_info[0] in NETWORK_FSTYPES:
        raise AutoSafeRefuse("network_volume")

    if os.path.isfile(path_str):
        return os.stat(path_str, follow_symlinks=False).st_size, 1, 0

    total = 0
    files = 0
    syms = 0
    stack = [path_str]
    while stack:
        current = stack.pop()
        current_block = _auto_safe_prefix_block(current)
        if current_block:
            raise AutoSafeRefuse(current_block)
        info = get_filesystem_info(current)
        if info is None or (not info[1]) or info[0] in NETWORK_FSTYPES:
            raise AutoSafeRefuse("network_volume")
        if info[2] and _auto_safe_prefix_block(info[2]):
            raise AutoSafeRefuse(_auto_safe_prefix_block(info[2]) or "network_volume")
        try:
            iterator = os.scandir(current)
        except OSError as exc:
            raise AutoSafeRefuse(f"unreadable:{exc}") from exc
        with iterator:
            for entry in iterator:
                if entry.name.startswith("._") or entry.name in NETWORK_DIR_BLACKLIST:
                    continue
                if entry.is_symlink():
                    try:
                        target = os.readlink(entry.path)
                    except OSError as exc:
                        raise AutoSafeRefuse(f"unreadable:{exc}") from exc
                    abs_target = target if os.path.isabs(target) else os.path.normpath(os.path.join(current, target))
                    blocked = _auto_safe_prefix_block(abs_target)
                    if blocked:
                        raise AutoSafeRefuse(blocked)
                    syms += 1
                    continue
                if entry.is_dir(follow_symlinks=False):
                    stack.append(entry.path)
                elif entry.is_file(follow_symlinks=False):
                    total += entry.stat(follow_symlinks=False).st_size
                    files += 1
    return total, files, syms


def system_disk_notification(volumes: List[VolumeStatus]) -> Optional[str]:
    for vol in volumes:
        if vol.mount_point == "/System/Volumes/Data" and vol.health_level == "critical" and vol.capacity_pct >= 82.0:
            return f"{vol.mount_point} 已用 {vol.capacity_pct:.1f}% ，剩余 {vol.avail_bytes} 字节"
    return None


def send_system_disk_notification(message: str) -> None:
    safe = message.replace("\\", " ").replace('"', " ")
    subprocess.run(
        ["/usr/bin/osascript", "-e", f'display notification "{safe}" with title "系统盘告急"'],
        check=False,
    )


def write_verified_json(path: str, payload: Dict[str, Any]) -> str:
    parent = os.path.dirname(path)
    if parent:
        os.makedirs(parent, exist_ok=True)
    raw = json.dumps(payload, indent=2, ensure_ascii=False, sort_keys=True).encode("utf-8")
    tmp = path + ".tmp"
    with open(tmp, "wb") as handle:
        handle.write(raw)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(tmp, path)
    with open(path, "rb") as handle:
        got = handle.read()
    if got != raw:
        raise AutoSafeRefuse("preimage_mismatch")
    json.loads(got.decode("utf-8"))
    return hashlib.sha256(got).hexdigest()


def copy_archive_payload(src: str, dest: str) -> None:
    parent = os.path.dirname(dest)
    os.makedirs(parent, exist_ok=True)
    if os.path.isfile(src) and not os.path.islink(src):
        shutil.copy2(src, dest)
        return
    os.makedirs(dest, exist_ok=True)
    dest_fs = get_filesystem_info(parent)
    dest_is_exfat = bool(dest_fs and dest_fs[0] in ("exfat", "msdos", "fat32"))
    flags = "-rltD" if dest_is_exfat else "-a"
    subprocess.run(
        ["/usr/bin/rsync", flags, "--exclude=._*", src.rstrip("/") + "/", dest.rstrip("/") + "/"],
        check=True,
    )


def _quarantine_partial(dest: str) -> Optional[str]:
    if not os.path.lexists(dest):
        return None
    incomplete = f"{dest}.incomplete-{time.strftime('%Y%m%dT%H%M%S')}"
    os.rename(dest, incomplete)
    return incomplete


def replace_source_with_symlink(src: str, dest: str) -> Optional[str]:
    parent = os.path.dirname(src)
    tmp_old = os.path.join(parent, f".{os.path.basename(src)}.curator-autosave-{os.getpid()}")
    if os.path.lexists(tmp_old):
        raise AutoSafeRefuse("autosave_exists")
    os.rename(src, tmp_old)
    try:
        os.symlink(dest, src)
        if os.readlink(src) != dest:
            raise AutoSafeRefuse("symlink_mismatch")
    except Exception:
        if os.path.islink(src):
            os.unlink(src)
        if os.path.lexists(tmp_old) and not os.path.lexists(src):
            os.rename(tmp_old, src)
        raise
    try:
        if os.path.isdir(tmp_old) and not os.path.islink(tmp_old):
            shutil.rmtree(tmp_old)
        elif os.path.lexists(tmp_old):
            os.unlink(tmp_old)
    except OSError:
        return tmp_old
    return None


def _plan_archives(candidates: List[ArchiveCandidate]) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    plans: List[Dict[str, Any]] = []
    holds: List[Dict[str, Any]] = []
    for cand in candidates:
        if cand.op != "move+symlink":
            holds.append(_hold(cand.rule_id, "archive_rule", "不可恢复删除", cand.op))
            continue
        blocked = auto_safe_block_reason(cand.source_path)
        if blocked:
            holds.append(_hold_from_block(cand.source_path, "archive_source", blocked))
            continue
        if not is_safe_to_modify(cand.source_path, allow_external_volumes=True):
            holds.append(_hold(cand.source_path, "archive_source", "落入禁止集", "protected"))
            continue
        if not is_archive_destination_ready(cand.dest_path) or _auto_safe_prefix_block(cand.dest_path):
            holds.append(_hold(cand.rule_id, "archive_rule", "目标卷未挂载", cand.dest_path))
            continue
        try:
            nbytes, nfiles, nsyms = exact_tree_stats(cand.source_path)
        except AutoSafeRefuse as exc:
            holds.append(_hold_from_block(cand.source_path, "archive_source", exc.reason))
            continue
        if nfiles <= 0:
            continue
        dest = cand.dest_path
        if os.path.lexists(dest):
            dest = f"{dest}_{time.strftime('%Y%m%dT%H%M%S')}"
        if os.path.lexists(dest):
            holds.append(_hold(cand.rule_id, "archive_rule", "目标已存在", dest))
            continue
        plans.append({
            "rule_id": cand.rule_id,
            "source": cand.source_path,
            "dest": dest,
            "file_count": nfiles,
            "byte_count": nbytes,
            "internal_symlinks": nsyms,
        })
    return plans, holds


def _symlink_hold(rec: BrokenSymlinkRecord) -> Optional[Dict[str, Any]]:
    raw = rec.old_target
    abs_target = raw if os.path.isabs(raw) else os.path.normpath(os.path.join(os.path.dirname(rec.link_path), raw))
    for path in (rec.link_path, abs_target, rec.suggested_new_target or ""):
        if not path:
            continue
        prefix = _auto_safe_prefix_block(path)
        if prefix == "hermes":
            return _hold(rec.link_path, "symlink", "已排除", "不打开 ~/.hermes")
        if prefix:
            return _hold(rec.link_path, "symlink", "落入禁止集", prefix)
    if rec.status == "forbidden":
        return _hold(rec.link_path, "symlink", "落入禁止集", "forbidden")
    parent = os.path.dirname(os.path.abspath(rec.link_path))
    if not is_local_filesystem(parent) or not is_safe_to_modify(rec.link_path, check_link_self=True):
        return _hold(rec.link_path, "symlink", "落入禁止集", "protected_or_network")
    new_target = rec.suggested_new_target
    if not new_target or not os.path.exists(new_target) or not is_local_filesystem(new_target):
        return _hold(rec.link_path, "symlink", "无本地目标", "orphan")
    blocked = auto_safe_block_reason(new_target)
    if blocked:
        return _hold_from_block(rec.link_path, "symlink", blocked)
    if not is_safe_to_modify(new_target, allow_external_volumes=True):
        return _hold(rec.link_path, "symlink", "落入禁止集", "protected_target")
    return None


def _fill_move_cold_estimates(
    rules: List[Dict[str, Any]],
    holds: List[Dict[str, Any]],
    archive_vault_root: str,
    databox_fallback_root: str,
) -> None:
    wanted = {row["id"] for row in holds if row["kind"] == "archive_rule" and row["reason"] == "不可恢复删除"}
    estimate_rules = [rule for rule in rules if rule["id"] in wanted]
    if not estimate_rules:
        return
    try:
        found = scan_archive_candidates(
            rules=estimate_rules,
            archive_vault_root=archive_vault_root,
            databox_fallback_root=databox_fallback_root,
        )
    except Exception:
        return
    totals: Dict[str, int] = {}
    blocked_ids = set()
    for cand in found:
        if auto_safe_block_reason(cand.source_path):
            blocked_ids.add(cand.rule_id)
            continue
        totals[cand.rule_id] = totals.get(cand.rule_id, 0) + cand.allocated_bytes
    for row in holds:
        if row["id"] in blocked_ids:
            row["reason"] = "落入禁止集"
            row["bytes"] = None
            row["detail"] = "estimate_blocked"
        elif row["id"] in totals and row.get("bytes") is None:
            row["bytes"] = totals[row["id"]]


def _estimate_cleanup_holds() -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    for rule in CLEANUP_RULES:
        paths = list(rule.get("paths") or [])
        hermes_paths = [path for path in paths if _auto_safe_prefix_block(path) == "hermes"]
        measurable = [path for path in paths if _auto_safe_prefix_block(path) is None]
        forbidden = [path for path in paths if _auto_safe_prefix_block(path) not in (None, "hermes")]
        if hermes_paths and not measurable:
            rows.append(_hold(rule["id"], "cleanup", "已排除", "不打开 ~/.hermes"))
            continue
        if forbidden and not measurable:
            rows.append(_hold_from_block(rule["id"], "cleanup", _auto_safe_prefix_block(forbidden[0]) or "forbidden"))
            continue
        total = 0
        truncated = False
        refused = False
        refuse_code = ""
        for raw in measurable:
            expanded = os.path.expanduser(raw)
            if os.path.islink(expanded):
                target = os.readlink(expanded)
                abs_target = target if os.path.isabs(target) else os.path.normpath(os.path.join(os.path.dirname(expanded), target))
                if _auto_safe_prefix_block(abs_target):
                    refused = True
                    refuse_code = _auto_safe_prefix_block(abs_target) or "forbidden"
                    break
            reason = auto_safe_block_reason(expanded) if os.path.lexists(expanded) else None
            if reason:
                refused = True
                refuse_code = reason
                break
            if not os.path.lexists(expanded):
                continue
            size, _count, trunc = measure_directory_fast(expanded, budget_seconds=0.6, follow_root_symlink=False)
            total += size
            truncated = truncated or trunc
        if refused:
            rows.append(_hold_from_block(rule["id"], "cleanup", refuse_code or "forbidden"))
            continue
        detail = "清空缓存不自动做"
        if hermes_paths:
            detail += "；Hermes 路径未估算"
        if truncated:
            detail += "；估计被截断"
        rows.append(_hold(rule["id"], "cleanup", "不可恢复删除", detail, total))
    return rows


def _estimate_uv_hold() -> Dict[str, Any]:
    row = _hold("uv-cache-prune", "maintenance", "不可恢复删除", "不执行 uv cache prune")
    path = "/Volumes/Cache/cache/uv"
    if not os.path.ismount("/Volumes/Cache") or not os.path.isdir(path):
        return row
    if auto_safe_block_reason(path):
        return row
    size, _count, trunc = measure_directory_fast(path, budget_seconds=1.2, follow_root_symlink=False)
    row["bytes"] = size
    if trunc:
        row["detail"] += "；估计被截断"
    return row


def render_weekly_hold(path: str, rows: List[Dict[str, Any]], volumes: List[VolumeStatus], mode: str) -> None:
    data = next((vol for vol in volumes if vol.mount_point == "/System/Volumes/Data"), None)
    lines = [
        f"# curator 周报保留项 {time.strftime('%Y-%m-%d')}",
        "",
        f"- mode: {mode}",
        "- 本文件只列候选，不执行删除、VACUUM、uv cache prune 或孤儿断链移除。",
        "",
    ]
    if data is not None:
        lines.append(f"- 系统盘: {data.mount_point} 已用 {data.capacity_pct:.1f}% 剩余 {data.avail_bytes} 字节")
        lines.append("")
    lines.extend(["| id 或路径 | 原因 | 估计体积 | 说明 |", "|---|---|---|---|"])
    for row in rows:
        if row.get("bytes") is None or row["reason"] in ("已排除", "落入禁止集"):
            size = "不估算"
        else:
            size = format_bytes(int(row["bytes"]))
        lines.append(
            f"| {str(row['id']).replace('|', '/')} | {row['reason']} | {size} | {str(row.get('detail') or '').replace('|', '/')} |"
        )
    parent = os.path.dirname(path)
    if parent:
        os.makedirs(parent, exist_ok=True)
    with open(path, "w", encoding="utf-8") as handle:
        handle.write("\n".join(lines) + "\n")


def _apply_archive_plan(plan: Dict[str, Any]) -> Dict[str, Any]:
    src = plan["source"]
    dest = plan["dest"]
    expected = (plan["byte_count"], plan["file_count"], plan["internal_symlinks"])
    if os.path.islink(src) or not os.path.exists(src) or os.path.lexists(dest):
        raise AutoSafeRefuse("source_or_dest_changed")
    if exact_tree_stats(src) != expected:
        raise AutoSafeRefuse("source_changed")
    try:
        copy_archive_payload(src, dest)
        if exact_tree_stats(dest) != expected:
            incomplete = _quarantine_partial(dest)
            raise AutoSafeRefuse("parity", incomplete)
    except AutoSafeRefuse:
        raise
    except Exception as exc:
        incomplete = _quarantine_partial(dest)
        raise AutoSafeRefuse(str(exc), incomplete) from exc
    leftover = replace_source_with_symlink(src, dest)
    if os.readlink(src) != dest or exact_tree_stats(dest) != expected:
        raise AutoSafeRefuse("post_swap_mismatch")
    return {"status": "archived", "rule_id": plan["rule_id"], "src": src, "dest": dest, "leftover": leftover}


def _apply_symlink_plan(plan: Dict[str, Any]) -> None:
    link = plan["link_path"]
    if not os.path.islink(link) or os.readlink(link) != plan["readlink"]:
        raise AutoSafeRefuse("readlink_changed")
    new_target = plan["new_target"]
    if _symlink_hold(BrokenSymlinkRecord(link, plan["readlink"], new_target, "repairable")):
        raise AutoSafeRefuse("forbidden")
    tmp_link = f"{link}.curator-tmp-{os.getpid()}"
    try:
        if os.path.lexists(tmp_link):
            os.unlink(tmp_link)
        os.symlink(new_target, tmp_link)
        os.replace(tmp_link, link)
    finally:
        if os.path.lexists(tmp_link):
            try:
                os.unlink(tmp_link)
            except OSError:
                pass
    if os.readlink(link) != new_target:
        raise AutoSafeRefuse("symlink_mismatch")


def run_auto_safe(
    apply: bool = False,
    rules: Optional[List[Dict[str, Any]]] = None,
    allow_ids: Optional[set] = None,
    search_roots: Optional[List[str]] = None,
    replacement_candidates: Optional[List[Tuple[str, str]]] = None,
    include_live_holds: Optional[bool] = None,
    backup_root: Optional[str] = None,
    weekly_report_path: Optional[str] = None,
    archive_vault_root: str = ARCHIVE_VAULT_ROOT,
    databox_fallback_root: str = DATABOX_ARCHIVE_FALLBACK,
    manifest_dir: str = ARCHIVE_MANIFEST_DIR,
    notify: bool = True,
) -> Dict[str, Any]:
    """
    Default dry-run. `--apply` only move+symlink archives and local symlink rewrites.
    Never calls clean, move_cold, VACUUM, orphan unlink, or a Hermes directory walk.
    """
    live = rules is None
    if rules is None:
        rules = ARCHIVE_RULES
    if allow_ids is None:
        allow_ids = AUTO_SAFE_ARCHIVE_IDS if live else {rule["id"] for rule in rules if rule.get("op") == "move+symlink"}
    if include_live_holds is None:
        include_live_holds = live
    stamp = time.strftime("%Y%m%dT%H%M%S")
    if backup_root is None:
        backup_root = os.path.expanduser(f"~/.shared/backups/curator-auto-{stamp}")
    if weekly_report_path is None:
        log_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "logs")
        weekly_report_path = os.path.join(log_dir, time.strftime("weekly-hold-%Y%m%d.md"))

    volumes = inspect_volumes(include_cloud_tier=False)
    notice = system_disk_notification(volumes)
    allowed, holds = partition_auto_safe_rules(rules, allow_ids)
    candidates = []
    if allowed:
        candidates = scan_archive_candidates(
            rules=allowed,
            archive_vault_root=archive_vault_root,
            databox_fallback_root=databox_fallback_root,
        )
    plans, plan_holds = _plan_archives(candidates)
    holds.extend(plan_holds)
    _fill_move_cold_estimates(rules, holds, archive_vault_root, databox_fallback_root)
    records = scan_broken_symlinks(
        search_roots=search_roots,
        replacement_candidates=replacement_candidates,
        allow_datapool_rewrite=False,
        avoid_forbidden_prefixes=True,
    )
    symlink_plans: List[Dict[str, Any]] = []
    for rec in records:
        held = _symlink_hold(rec)
        if held:
            holds.append(held)
        else:
            symlink_plans.append({
                "link_path": rec.link_path,
                "readlink": rec.old_target,
                "new_target": rec.suggested_new_target,
            })
    holds.extend(dict(row) for row in STATIC_AUTO_SAFE_HOLDS)
    if include_live_holds:
        holds.extend(_estimate_cleanup_holds())
        holds = [row for row in holds if row["id"] != "uv-cache-prune"]
        holds.append(_estimate_uv_hold())

    preimage = {
        "schema": "curator-auto-safe-preimage-v1",
        "created": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "mode": "apply" if apply else "dry-run",
        "archives": plans,
        "symlinks": symlink_plans,
    }
    preimage_path = os.path.join(backup_root, "preimage.json")
    try:
        preimage_sha = write_verified_json(preimage_path, preimage)
    except Exception as exc:
        return {
            "ok": False,
            "exit_code": 2,
            "error": str(exc),
            "applied": False,
            "backup_root": backup_root,
        }

    mode = "apply" if apply else "dry-run"
    failure: Optional[Dict[str, Any]] = None
    archived: List[Dict[str, Any]] = []
    rewritten: List[Dict[str, Any]] = []
    if apply:
        for plan in plans:
            try:
                archived.append(_apply_archive_plan(plan))
            except AutoSafeRefuse as exc:
                failure = {
                    "op": "archive",
                    "rule_id": plan["rule_id"],
                    "source": plan["source"],
                    "dest": plan["dest"],
                    "reason": exc.reason,
                    "incomplete_path": exc.incomplete_path,
                }
                break
        if failure is None:
            for plan in symlink_plans:
                try:
                    _apply_symlink_plan(plan)
                    rewritten.append(plan)
                except AutoSafeRefuse as exc:
                    failure = {"op": "symlink", "link_path": plan["link_path"], "reason": exc.reason}
                    break
        result_payload = {"preimage": preimage_path, "archived": archived, "rewritten": rewritten, "failure": failure}
        write_verified_json(os.path.join(backup_root, "preimage-result.json"), result_payload)
        if archived:
            ledger = {
                "schema": "mac-tiered-curator-archive-v1",
                "timestamp": stamp,
                "actions": archived,
            }
            write_verified_json(os.path.join(backup_root, "archive-ledger.json"), ledger)
            if is_archive_destination_ready(manifest_dir):
                write_verified_json(os.path.join(manifest_dir, f"curator_auto_safe_{stamp}.json"), ledger)

    notification_sent = False
    if apply and notify and notice:
        send_system_disk_notification(notice)
        notification_sent = True
    render_weekly_hold(weekly_report_path, holds, volumes, mode)
    summary = {
        "ok": failure is None,
        "exit_code": 0 if failure is None else 3,
        "applied": bool(apply and failure is None and (archived or rewritten)),
        "dry_run": not apply,
        "backup_root": backup_root,
        "preimage_path": preimage_path,
        "preimage_sha256": preimage_sha,
        "weekly_report_path": weekly_report_path,
        "archive_plans": plans,
        "symlink_plans": symlink_plans,
        "archived": archived,
        "rewritten": rewritten,
        "failure": failure,
        "hold_count": len(holds),
        "holds": holds,
        "would_notify": notice is not None,
        "notification_sent": notification_sent,
        "notification_message": notice,
        "volumes": [dataclasses.asdict(vol) for vol in volumes],
    }
    write_verified_json(os.path.join(backup_root, "auto-safe-result.json"), summary)
    return summary


# ---------------------------------------------------------------------------
# CLI Entrypoint
# ---------------------------------------------------------------------------

def build_full_report() -> Dict[str, Any]:
    vols = inspect_volumes()
    candidates = scan_cleanup_candidates(budget_per_path=0.9)
    archive_candidates = scan_archive_candidates()
    broken_links = scan_broken_symlinks()
    sqlite_dbs = analyze_sqlite_databases()
    projects = scan_project_artifacts(min_stale_days=7, max_depth=3)
    leftovers = scan_container_leftovers()
    universal = scan_universal_binaries()

    by_vol: Dict[str, int] = {}
    for c in candidates:
        by_vol[c.physical_volume] = by_vol.get(c.physical_volume, 0) + c.allocated_bytes

    archive_by_vol: Dict[str, int] = {}
    for a in archive_candidates:
        archive_by_vol[a.source_volume] = archive_by_vol.get(a.source_volume, 0) + a.allocated_bytes

    return {
        "volumes": [dataclasses.asdict(v) for v in vols],
        "reclaimable_by_volume": {k: {"bytes": v, "human": format_bytes(v)} for k, v in by_vol.items()},
        "archivable_by_volume": {k: {"bytes": v, "human": format_bytes(v)} for k, v in archive_by_vol.items()},
        "cleanup_candidates": [dataclasses.asdict(c) for c in candidates],
        "archive_candidates": [dataclasses.asdict(a) for a in archive_candidates],
        "broken_symlinks": [dataclasses.asdict(b) for b in broken_links],
        "sqlite_bloat": sqlite_dbs,
        "stale_project_artifacts": projects,
        "container_leftovers": leftovers,
        "universal_binaries": universal,
    }


def print_human_report(report: Dict[str, Any]) -> None:
    print("=" * 78)
    print("🧭 mac-tiered-curator: 四层多盘态势与逆向级空间治理报告")
    print("=" * 78)

    print("\n[1] 四层多盘水位态势 (Tiered Multi-Volume Status)")
    for v in report["volumes"]:
        badge = "🔴 CRITICAL" if v["health_level"] == "critical" else ("🟡 ELEVATED" if v["health_level"] == "elevated" else "🟢 HEALTHY")
        print(
            f"  {badge:11s} | {v['mount_point']:22s} ({v['fstype']}) | 已用 {v['capacity_pct']:5.1f}% "
            f"(可用 {format_bytes(v['avail_bytes']):>8s} / 总计 {format_bytes(v['total_bytes']):>8s}) — {v['tier_role']}"
        )

    print("\n[2] 按物理卷汇总的可立即清理缓存 (Symlink-Aware Cleanup Candidates)")
    for vol, info in report["reclaimable_by_volume"].items():
        print(f"  📦 {vol:24s}: 可直接清理 {info['human']}")
    print("  ------------------------------------------------------------------------")
    for c in report["cleanup_candidates"][:15]:
        link_tag = "🔗[软链穿透保护]" if c["is_symlink_root"] else "📁[直连目录]    "
        trunc_tag = "+" if c["truncated"] else " "
        print(
            f"  • {format_bytes(c['allocated_bytes']):>8s}{trunc_tag} | {c['physical_volume']:20s} | "
            f"{link_tag} {c['rule_id']:28s} ({c['logical_path']})"
        )

    print("\n[2.5] 可向兜底盘冷迁移归档项 (Cold-Tier Archive & Relocate)")
    if not is_archive_destination_ready(ARCHIVE_VAULT_ROOT):
        print("  💡 提示: 未检测到独立冷归档盘 (默认 /Volumes/archive)，冷归档已安全跳过（纯缓存清理不受任何影响）。")
        print("     若需开启多盘冷热分流兜底，可外接移动硬盘并命名为 archive，或配置 CURATOR_ARCHIVE_ROOT 环境变量。")
    for vol, info in report.get("archivable_by_volume", {}).items():
        print(f"  🧊 {vol:24s}: 可无损迁出 {info['human']}")
    print("  ------------------------------------------------------------------------")
    for a in report.get("archive_candidates", [])[:15]:
        op_tag = "🔗[迁入冷盘+留软链]" if a["op"] == "move+symlink" else "📦[纯冷归档落盘]  "
        print(
            f"  • {format_bytes(a['allocated_bytes']):>8s}  | {a['source_volume']:20s} -> {a['dest_volume']:16s} | "
            f"{op_tag} [{a['rule_id']}] {a['source_path']}"
        )

    print("\n[3] AI Agent SQLite 状态库体积与碎片诊断 (SQLite Bloat Analysis)")
    for db in report["sqlite_bloat"]:
        if "error" in db:
            print(f"  • {format_bytes(db['allocated_bytes']):>8s} | {db['path']} (读取跳过: {db['error']})")
        else:
            print(
                f"  • {format_bytes(db['allocated_bytes']):>8s} | 可无损 VACUUM 回收: {format_bytes(db['reclaimable_bytes']):>8s} | {db['path']}"
            )

    print(f"\n[4] 悬空失效软链接诊断 (Broken Symlinks: 共发现 {len(report['broken_symlinks'])} 处)")
    for b in report["broken_symlinks"][:12]:
        if b["suggested_new_target"]:
            print(f"  🔧 [可自动重绑] {b['link_path']} -> {b['suggested_new_target']}")
        else:
            print(f"  ⚠️ [孤儿失效链] {b['link_path']} -/-> {b['old_target']}")

    print(f"\n[5] 项目级陈旧构建产物 (Project Marker Artifacts: 共发现 {len(report['stale_project_artifacts'])} 处)")
    for p in report["stale_project_artifacts"][:10]:
        print(
            f"  • {format_bytes(p['allocated_bytes']):>8s} | {p['stale_days']:5.0f} 天未动 | "
            f"[{p['rule_id']}] {p['artifact_path']}"
        )

    print(f"\n[6] 沙盒容器卸载残留 (Container Leftovers: 共发现 {len(report['container_leftovers'])} 处)")
    for lo in report["container_leftovers"][:8]:
        print(
            f"  • {format_bytes(lo['allocated_bytes']):>8s} | 已卸载应用: {lo['former_bundle_path']} "
            f"({lo['container_path']})"
        )

    print(f"\n[7] Universal Binary 胖二进制可剥离 x86_64 切片 (共 {len(report['universal_binaries'])} 个应用)")
    for u in report["universal_binaries"][:8]:
        print(
            f"  • 可省 {format_bytes(u['x86_64_slice_bytes']):>8s} (总 {format_bytes(u['total_size']):>8s}) | {u['app_name']}"
        )
    print("=" * 78)


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="mac-tiered-curator CLI")
    sub = parser.add_subparsers(dest="cmd")

    p_scan = sub.add_parser("scan", help="Run full tiered multi-volume & AI-stack diagnostic scan")
    p_scan.add_argument("--json", action="store_true", help="Output JSON")

    p_clean = sub.add_parser("clean", help="Clean selected rule IDs (preserving symlink topology)")
    p_clean.add_argument("--rules", nargs="+", required=True, help="Rule IDs to clean (or 'safe_defaults')")
    p_clean.add_argument("--apply", action="store_true", help="Actually delete files (default is dry-run)")

    p_arch = sub.add_parser("archive", help="Relocate cold data to /Volumes/archive safety-net with verification & manifest")
    p_arch.add_argument("--rules", nargs="+", required=True, help="Archive rule IDs to execute (or 'all')")
    p_arch.add_argument("--apply", action="store_true", help="Execute migration (default is dry-run)")

    p_sym = sub.add_parser("fix-symlinks", help="Repair or remove broken symlinks")
    p_sym.add_argument("--remove-orphans", action="store_true", help="Also unlink unrepairable broken symlinks")
    p_sym.add_argument("--apply", action="store_true", help="Apply changes (default is dry-run)")

    p_vac = sub.add_parser("vacuum-sqlite", help="Run lossless SQLite VACUUM on bloated agent databases")
    p_vac.add_argument("--min-reclaim-mb", type=float, default=10.0, help="Minimum reclaimable MB to vacuum")
    p_vac.add_argument("--apply", action="store_true", help="Actually execute VACUUM (default is dry-run)")

    p_auto = sub.add_parser(
        "auto-safe",
        help="Move+symlink cold archive and local symlink rewrite only (default dry-run; no clean, move_cold, or VACUUM)",
    )
    p_auto.add_argument("--apply", action="store_true", help="Execute rule A and rule B after a verified preimage")
    p_auto.add_argument("--json", action="store_true", help="Output JSON summary")

    p_routine = sub.add_parser("routine", help="Run unified 5-phase periodic maintenance (symlinks + safe caches + SQLite VACUUM + cold archive)")
    p_routine.add_argument("--min-reclaim-mb", type=float, default=10.0, help="Minimum reclaimable SQLite MB to vacuum")
    p_routine.add_argument("--apply", action="store_true", help="Apply periodic maintenance (default is dry-run)")
    p_routine.add_argument("--json", action="store_true", help="Output JSON summary")

    p_maint = sub.add_parser("maint", help="List or execute reverse-engineered macOS maintenance tasks")
    p_maint.add_argument("--task", choices=list(MAINTENANCE_TASKS.keys()), help="Task ID to run")
    p_maint.add_argument("--apply", action="store_true", help="Execute non-sudo task or print sudo command")

    args = parser.parse_args(argv)
    if not args.cmd or args.cmd == "scan":
        rep = build_full_report()
        if getattr(args, "json", False):
            print(json.dumps(rep, indent=2, ensure_ascii=False))
        else:
            print_human_report(rep)
        return 0

    if args.cmd == "clean":
        candidates = scan_cleanup_candidates(budget_per_path=1.5)
        selected_ids = set(args.rules)
        if "safe_defaults" in selected_ids:
            selected_ids.update(r["id"] for r in CLEANUP_RULES if r["default_selected"] and r["risk"] == "safe")
        dry = not args.apply
        total_freed = 0
        for c in candidates:
            if c.rule_id in selected_ids:
                freed, cnt = clean_directory_contents_preserving_root(c.logical_path, dry_run=dry)
                total_freed += freed
                mode = "[DRY-RUN]" if dry else "[CLEANED]"
                print(
                    f"{mode} {c.rule_id} ({c.logical_path} -> {c.resolved_path} on {c.physical_volume}) "
                    f"-> {format_bytes(freed)} ({cnt} items)"
                )
        print(f"Total {'estimated' if dry else 'released'}: {format_bytes(total_freed)}")
        return 0

    if args.cmd == "archive":
        all_cands = scan_archive_candidates()
        selected_ids = set(args.rules)
        if "all" in selected_ids:
            selected_cands = all_cands
        else:
            selected_cands = [c for c in all_cands if c.rule_id in selected_ids]
        res = execute_archive_migration(selected_cands, dry_run=not args.apply)
        for act in res["actions"]:
            mode = "[DRY-RUN]" if res["dry_run"] else "[ARCHIVED]"
            print(
                f"{mode} ({act['op']}) {act['rule_id']}: {act['src']} -> {act['dest']} "
                f"({format_bytes(act['bytes'])}, {act['files']} files)"
            )
        print(f"Total {'planned' if res['dry_run'] else 'migrated'}: {res['total_human']} | By volume: {res['by_source_volume']}")
        if res.get("manifest_path"):
            print(f"Manifest written to: {res['manifest_path']}")
        return 0

    if args.cmd == "fix-symlinks":
        records = scan_broken_symlinks()
        stats = repair_or_remove_broken_symlinks(records, remove_orphans=args.remove_orphans, dry_run=not args.apply)
        print(json.dumps({"dry_run": not args.apply, **stats}, indent=2, ensure_ascii=False))
        return 0

    if args.cmd == "vacuum-sqlite":
        dbs = analyze_sqlite_databases()
        threshold = int(args.min_reclaim_mb * 1024 * 1024)
        for db in dbs:
            reclaim = db.get("reclaimable_bytes", 0)
            if reclaim < threshold:
                continue
            res = vacuum_sqlite_database_safe(db["path"], dry_run=not args.apply)
            if res["status"] == "dry_run":
                print(f"[DRY-RUN] Would VACUUM {db['path']} (estimated reclaim: {format_bytes(reclaim)})")
            elif res["status"] == "vacuumed":
                print(
                    f"[VACUUMED] {db['path']}: {format_bytes(res['before_bytes'])} -> "
                    f"{format_bytes(res['after_bytes'])} (saved {format_bytes(res['saved_bytes'])})"
                )
            else:
                print(f"[SKIPPED/LOCKED] {db['path']}: {res.get('error') or res.get('reason')}")
        return 0

    if args.cmd == "auto-safe":
        summary = run_auto_safe(apply=args.apply)
        if args.json:
            print(json.dumps(summary, indent=2, ensure_ascii=False))
        else:
            mode = "DRY-RUN" if summary.get("dry_run", True) else ("STOPPED" if summary.get("failure") else "APPLIED")
            print(f"=== mac-tiered-curator auto-safe [{mode}] ===")
            print(f"预映像: {summary.get('preimage_path')} sha256={summary.get('preimage_sha256')}")
            print(f"周报: {summary.get('weekly_report_path')}")
            print(f"冷归档计划: {len(summary.get('archive_plans') or [])} 项")
            for plan in (summary.get("archive_plans") or [])[:30]:
                print(
                    f"  • [{plan['rule_id']}] {plan['source']} -> {plan['dest']} "
                    f"({plan['file_count']} files, {plan['byte_count']} bytes)"
                )
            print(f"断链改写计划: {len(summary.get('symlink_plans') or [])} 项")
            for plan in (summary.get("symlink_plans") or [])[:30]:
                print(f"  • {plan['link_path']} readlink={plan['readlink']} -> {plan['new_target']}")
            print(f"周报保留: {summary.get('hold_count', 0)} 条")
            if summary.get("would_notify"):
                print(f"系统盘告急: {summary.get('notification_message')}")
            else:
                data = next((v for v in summary.get("volumes") or [] if v.get("mount_point") == "/System/Volumes/Data"), None)
                if data:
                    print(f"系统盘: {data['mount_point']} 已用 {data['capacity_pct']}% 剩余 {data['avail_bytes']} 字节 — 未通知")
            print("已通知" if summary.get("notification_sent") else "未发送通知")
            if summary.get("failure"):
                print(f"已停止: {summary['failure']}")
            if summary.get("dry_run"):
                print("未执行 --apply")
            if summary.get("error"):
                print(f"预映像失败: {summary['error']}")
        return int(summary.get("exit_code") or 0)

    if args.cmd == "routine":
        summary = run_periodic_routine(apply=args.apply, min_reclaim_mb=args.min_reclaim_mb)
        if args.json:
            print(json.dumps(summary, indent=2, ensure_ascii=False))
        else:
            mode = "DRY-RUN" if summary["dry_run"] else "APPLIED"
            print(f"=== mac-tiered-curator Periodic Routine [{mode}] ({summary['timestamp']}) ===")
            print(f"• Symlinks auto-healed : {summary['symlinks']['repaired']} repaired, {summary['symlinks']['skipped']} skipped")
            print(f"• Safe caches cleaned  : {summary['cleanup']['total_freed_human']} ({len(summary['cleanup']['actions'])} rules, BundleMigration: {summary['cleanup']['bundle_migration']['freed_human']})")
            print(f"• SQLite compacted     : {summary['sqlite_vacuum']['total_saved_human']} ({len(summary['sqlite_vacuum']['actions'])} DBs)")
            print(f"• Cold archive migrated: {summary['archive']['total_human']} ({len(summary['archive']['actions'])} items)")
            for v in summary["volumes_after"]:
                print(f"  - {v['mount_point']:22s}: {v['capacity_pct']:5.1f}% used ({format_bytes(v['avail_bytes'])} free) [{v['health_level'].upper()}]")
        return 0

    if args.cmd == "maint":
        if not args.task:
            for tid, info in MAINTENANCE_TASKS.items():
                sudo_tag = "[需管理员权限]" if info["requires_sudo"] else "[用户态可直接执行]"
                print(f"  {tid:22s} | {sudo_tag} {info['title']}\n    $ {info['cmd']}")
            return 0
        task = MAINTENANCE_TASKS[args.task]
        if task["requires_sudo"] or not args.apply:
            print(f"# {task['title']}\n{task['cmd']}")
        else:
            subprocess.run(task["cmd"], shell=True, check=False)
        return 0

    return 0


if __name__ == "__main__":
    sys.exit(main())


