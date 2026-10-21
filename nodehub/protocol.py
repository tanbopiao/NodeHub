"""Command bus protocol (distilled from NTFY-CONNECT-001).

Messages are JSON text with an embedded identity block:
  {"proto": ..., "zr_did": ..., "src": ..., "task_id": ...,
   "cmd": ..., "timeout": ..., "type": "cmd"|"done"|"online"|"heartbeat"}

Transport is pluggable: any channel that delivers strings (pub/sub topic,
git "command slot" repo, HTTP poll) works. Workers only need READ access
to the command channel; results go back over an authenticated endpoint.
"""
from __future__ import annotations

import json
import time
import uuid
from typing import Any, Callable, Dict, Optional, List

PROTO_VERSION = "NTFY-CONNECT-001"
DEFAULT_DID = "DID-BR-000002"


def new_task_id(prefix: str = "t") -> str:
    return f"{prefix}-{int(time.time())}-{uuid.uuid4().hex[:6]}"


def encode_cmd(cmd: str, *, src: str = "NN-LOCAL-DEV-001", timeout: int = 300,
               task_id: Optional[str] = None, node: Optional[str] = None,
               did: str = DEFAULT_DID) -> str:
    """Encode a command as a protocol JSON string. ``node=None`` broadcasts."""
    msg: Dict[str, Any] = {
        "proto": PROTO_VERSION, "zr_did": did, "src": src,
        "task_id": task_id or new_task_id(),
        "cmd": cmd, "timeout": timeout, "type": "cmd",
    }
    if node:
        msg["node"] = node
    return json.dumps(msg, ensure_ascii=False)


def decode_msg(raw: str) -> Optional[Dict]:
    try:
        d = json.loads(raw)
        return d if isinstance(d, dict) else None
    except Exception:
        return None


def is_trusted(msg: Optional[Dict], *, did: str = DEFAULT_DID,
               proto: str = PROTO_VERSION) -> bool:
    """Identity check: protocol tag and DID must both match."""
    return (isinstance(msg, dict)
            and msg.get("proto") == proto
            and msg.get("zr_did") == did)


def encode_result(task_id: str, node: str, *, out: str = "", code: int = 0,
                  did: str = DEFAULT_DID, mtype: str = "done") -> str:
    return json.dumps({"type": mtype, "proto": PROTO_VERSION, "zr_did": did,
                       "node": node, "task_id": task_id, "out": out,
                       "code": code, "ts": int(time.time())},
                      ensure_ascii=False)


class CommandBus:
    """Bidirectional command channel.

    ``fetch``   — returns a list of raw messages waiting on the command channel
    ``publish`` — delivers a raw result/heartbeat message upstream
    Both are injectable; the bus itself is transport-agnostic and offline-testable.
    """

    def __init__(self, node_id: str, *, fetch: Callable[[], List[str]],
                 publish: Callable[[str], Any], did: str = DEFAULT_DID):
        self.node_id = node_id
        self._fetch = fetch
        self._publish = publish
        self.did = did

    def poll(self) -> List[Dict]:
        """Fetch, decode and identity-filter pending commands."""
        out = []
        for raw in self._fetch():
            msg = decode_msg(raw)
            if is_trusted(msg, did=self.did) and msg.get("type") == "cmd":
                # a targeted message for another node is skipped, not failed
                if msg.get("node") and msg["node"] != self.node_id:
                    continue
                out.append(msg)
        return out

    def send_result(self, task_id: str, *, out: str = "", code: int = 0) -> Any:
        return self._publish(encode_result(task_id, self.node_id,
                                           out=out, code=code, did=self.did))

    def send_heartbeat(self) -> Any:
        return self._publish(encode_result("", self.node_id,
                                           mtype="heartbeat", did=self.did))
