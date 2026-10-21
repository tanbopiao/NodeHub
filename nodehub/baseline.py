"""Node baseline verification — capability level pinned to content hashes.

Distilled from verify_node_baseline.py: a node that boots from a Git repo
must prove its kernel assets match an official baseline before it earns a
capability level. Missing assets => level lockdown; hash mismatch =>
suspected tampering; exact match => full level.

The official hash manifest is injectable (a callable returning
{filename: sha256-or-None}); offline mode verifies against a local manifest.
"""
from __future__ import annotations

import hashlib
import os
from typing import Callable, Dict, Optional

EXIT_OK, EXIT_MISSING, EXIT_MISMATCH, EXIT_USAGE = 0, 1, 2, 3


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


class BaselineVerifier:
    def __init__(self, baseline_id: str, level: str,
                 official_hashes: Optional[Dict[str, Optional[str]]] = None,
                 fetch_official: Optional[Callable[[], Dict[str, str]]] = None):
        self.baseline_id = baseline_id
        self.level = level
        self._official = official_hashes or {}
        self._fetch = fetch_official

    def official(self) -> Dict[str, str]:
        if self._fetch:
            got = self._fetch() or {}
            if got:
                return got
        return {k: v for k, v in self._official.items() if v}

    def scan(self, root: str, critical_assets: Dict[str, Optional[str]]) -> Dict[str, str]:
        """Return {relative_path: sha256} for present files; '' marks missing."""
        found: Dict[str, str] = {}
        for name in critical_assets:
            p = os.path.join(root, name)
            found[name] = sha256_file(p) if os.path.exists(p) else ""
        return found

    def verify(self, root: str, critical_assets: Dict[str, Optional[str]]) -> Dict:
        found = self.scan(root, critical_assets)
        official = self.official()
        missing = [k for k, v in found.items() if v == ""]
        mismatched = []
        for k, local_hash in found.items():
            if not local_hash:
                continue
            expect = official.get(k)
            if expect and local_hash != expect:
                mismatched.append(k)
        ok = not missing and not mismatched
        return {
            "baseline": self.baseline_id,
            "level": self.level if ok else "LOCKED",
            "verified": ok,
            "missing": missing,
            "mismatched": mismatched,
            "exit_code": EXIT_OK if ok else (EXIT_MISSING if missing else EXIT_MISMATCH),
        }
