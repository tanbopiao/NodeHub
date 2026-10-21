"""SlotWorker — credential-free command worker loop.

Distilled from zr_node_git.py: a worker node polls a read-only "command
slot" (git pull of a public repo, pub/sub topic, HTTP poll), executes
whitelisted commands, and reports results/heartbeats to an authenticated
endpoint. The worker NEVER needs push credentials for the command channel.

Idempotency: processed task_ids persist to a done-file, so replays after
restart are no-ops. Backoff: transient errors back off 5→60s, success resets.
"""
from __future__ import annotations

import json
import os
import subprocess
import threading
import time
from typing import Any, Callable, Dict, List, Optional

from .protocol import CommandBus
from .safety import check_safe

MIN_BACKOFF, MAX_BACKOFF = 5, 60


class SlotWorker:
    def __init__(self, bus: CommandBus, *,
                 done_file: Optional[str] = None,
                 executor: Optional[Callable[[str], Any]] = None,
                 safety: Callable[[str], Any] = check_safe,
                 report_endpoint: Optional[str] = None,
                 auth_headers: Optional[Dict[str, str]] = None):
        self.bus = bus
        self.done_file = done_file
        self._executor = executor or self._shell_exec
        self._safety = safety
        self._endpoint = report_endpoint
        self._headers = auth_headers or {}
        self._done: Dict[str, int] = self._load_done()
        self._stop = threading.Event()

    # -- persistence / idempotency -----------------------------------------
    def _load_done(self) -> Dict[str, int]:
        if self.done_file and os.path.exists(self.done_file):
            try:
                with open(self.done_file, encoding="utf-8") as f:
                    return json.load(f)
            except Exception:
                pass
        return {}

    def _mark_done(self, task_id: str, code: int) -> None:
        self._done[task_id] = code
        if self.done_file:
            try:
                os.makedirs(os.path.dirname(self.done_file) or ".", exist_ok=True)
                with open(self.done_file, "w", encoding="utf-8") as f:
                    json.dump(self._done, f)
            except Exception:
                pass

    # -- execution -----------------------------------------------------------
    @staticmethod
    def _shell_exec(cmd: str):
        try:
            r = subprocess.run(cmd, shell=True, capture_output=True,
                               text=True, timeout=90)
            return r.returncode, (r.stdout or ""), (r.stderr or "")
        except Exception as e:
            return -1, "", str(e)

    def handle(self, msg: Dict) -> Optional[Dict]:
        """Execute one command message (safety-gated, idempotent)."""
        task_id = msg.get("task_id", "")
        if not task_id or task_id in self._done:
            return None  # replay after restart: already handled
        ok, reason = self._safety(msg.get("cmd", ""))
        if not ok:
            res = {"task_id": task_id, "code": 126, "out": f"blocked: {reason}"}
        else:
            code, out, err = self._executor(msg["cmd"])
            res = {"task_id": task_id, "code": code, "out": out or err}
        self._mark_done(task_id, res["code"])
        self.bus.send_result(task_id, out=res["out"], code=res["code"])
        return res

    # -- main loop -----------------------------------------------------------
    def run_once(self) -> int:
        """Poll once; returns number of commands executed."""
        msgs = self.bus.poll()
        executed = 0
        for m in msgs:
            if self.handle(m) is not None:
                executed += 1
        return executed

    def run_forever(self, interval: float = 30.0,
                    heartbeat_every: int = 10) -> None:  # pragma: no cover
        backoff = MIN_BACKOFF
        beats = 0
        while not self._stop.is_set():
            try:
                n = self.run_once()
                backoff = MIN_BACKOFF
                beats += 1
                if heartbeat_every and beats % heartbeat_every == 0:
                    self.bus.send_heartbeat()
                if n == 0:
                    time.sleep(interval)
            except Exception:
                time.sleep(backoff)
                backoff = min(backoff * 2, MAX_BACKOFF)

    def stop(self) -> None:
        self._stop.set()
