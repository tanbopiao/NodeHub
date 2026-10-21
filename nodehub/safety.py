"""Safety gate for remotely dispatched commands.

Distilled from zr_node_protocol.py: dangerous-pattern blacklist plus an
allowed-prefix whitelist. Default-deny: a command runs only if it matches
a whitelisted prefix AND hits no blacklist pattern.
"""
from __future__ import annotations

from typing import List, Optional, Tuple

DEFAULT_DANGEROUS: List[str] = [
    "rm -rf /", "rm -rf /*", "mkfs", "dd if=", ":(){", "sh -c '", 'sh -c"',
    "chmod 777 /", "passwd", "reboot", "shutdown", "mv /etc/", "> /dev/sd",
    "fdisk", "iptables -f", "systemctl stop", "kill -9 1", "mv /root",
    "> /etc/", ">> /etc/", "> /etc", "> /usr/", "> /var/",
    "| sh", "|bash", "| sh -", "| bash", "| wget", "| sh ", "| bash ",
    "&& sh", "&& bash", "; sh ", "; bash ",
]

DEFAULT_ALLOWED: List[str] = [
    "echo", "hostname", "uname", "pwd", "date", "uptime", "df ", "free ",
    "python3 -v", "python3 -c", "ps aux", "ss -t", "netstat -t", "curl -s",
    "ls ", "cat ", "head ", "tail ", "grep ", "git status", "git pull",
    "git -c", "git clone", "git fetch", "cp ", "mkdir -p", "find ",
    "wc -l", "du -sh", "which ", "env ", "whoami", "id ", "jobs",
]


def check_safe(cmd: str, *, dangerous: Optional[List[str]] = None,
               allowed: Optional[List[str]] = None) -> Tuple[bool, str]:
    """Return ``(ok, reason)``. Default-deny: first segment must start with
    an allowed prefix; any blacklist hit anywhere in the command rejects it.
    """
    dangerous = dangerous if dangerous is not None else DEFAULT_DANGEROUS
    allowed = allowed if allowed is not None else DEFAULT_ALLOWED
    c = (cmd or "").strip().lower()
    if not c:
        return False, "empty"
    for bad in dangerous:
        if bad in c:
            return False, f"blacklist:{bad}"
    # first pipeline/chain segment decides the prefix verdict
    prefix = c.split(";")[0].split("&&")[0].split("|")[0].strip()
    for ok in allowed:
        if prefix.startswith(ok.lower()):
            return True, "ok"
    return False, f"not-allowed-prefix:{prefix[:40]}"
