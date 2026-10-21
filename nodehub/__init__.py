"""nodehub — Git-bootstrapped node mesh for autonomous agent fleets.

Distilled from ZONGYUAN-ROOT (branch converge-20260928), files:
07_代码与脚本/zr_node_protocol.py · zr_node_git.py ·
verify_node_baseline.py · zr_bootstrap.sh

Design (carried over from the upstream NTFY-CONNECT-001 / git-slot design):
  - commands reach nodes through a read-only channel (git pull of a public
    "command slot" repo or a pub/sub topic) — worker nodes hold NO push
    credentials
  - results/heartbeats flow back through an authenticated report endpoint
    (token via environment only)
  - every inbound message is identity-checked (protocol + DID) and every
    command passes a blacklist+whitelist safety gate
  - node identity: config file > env var > hostname-derived
  - baseline verification pins node capability level to content hashes
"""
from .protocol import (PROTO_VERSION, CommandBus, decode_msg, encode_cmd,
                       is_trusted, new_task_id)
from .safety import check_safe
from .baseline import BaselineVerifier, sha256_file
from .worker import SlotWorker

__version__ = "0.1.0"
__all__ = ["CommandBus", "SlotWorker", "BaselineVerifier", "check_safe",
           "encode_cmd", "decode_msg", "is_trusted", "new_task_id",
           "sha256_file", "PROTO_VERSION", "__version__"]
