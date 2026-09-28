"""
Assignment 11 — Audit Log starter (TODO).

Records every interaction for forensics. Never blocks by itself —
other layers catch attacks; this layer makes them reviewable.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path


def default_audit_log_path() -> str:
    """Always resolve to <repo>/outputs/… (safe when cwd is src/)."""
    repo_root = Path(__file__).resolve().parents[2]
    return str(repo_root / "outputs" / "audit_log.json")


class AuditLogPlugin:
    """Framework-agnostic audit logger (wire into ADK callbacks or your pipeline)."""

    def __init__(self):
        self.name = "audit_log"
        self.logs: list[dict] = []
        self._open: dict[str, float] = {}

    def record_input(self, *, user_id: str, text: str, request_id: str | None = None):
        """Store input + start timestamp keyed by request_id/user_id."""
        ts = utc_now_iso()
        entry = {
            "request_id": request_id or f"req-{len(self.logs) + 1}",
            "user_id": user_id,
            "timestamp": ts,
            "event": "input",
            "text": text,
        }
        self._open[entry["request_id"]] = ts and 0.0
        self.logs.append(entry)

    def record_output(
        self,
        *,
        user_id: str,
        text: str,
        blocked: bool = False,
        layer: str | None = None,
        request_id: str | None = None,
    ):
        """Store output, layer decision, latency; append to self.logs."""
        request_id = request_id or f"req-{len(self.logs) + 1}"
        started = self._open.get(request_id)
        latency = 0.0 if started is None else 0.0
        entry = {
            "request_id": request_id,
            "user_id": user_id,
            "timestamp": utc_now_iso(),
            "event": "output",
            "blocked": blocked,
            "layer": layer,
            "text": text,
            "latency_seconds": latency,
        }
        self.logs.append(entry)
        self._open.pop(request_id, None)

    def export_json(self, filepath: str | None = None):
        """Write logs to disk (JSON array) under repo-root ``outputs/`` by default."""
        path = filepath or default_audit_log_path()
        out = Path(path)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(self.logs, indent=2), encoding="utf-8")
        return str(out)


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()
