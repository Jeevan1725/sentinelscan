"""Observability: every step, tool call and pause - with the reason."""
import json
import threading
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path


@dataclass
class TraceEvent:
    step: int
    agent: str
    action: str
    detail: str
    reason: str
    ts: str = field(default_factory=lambda: datetime.now().isoformat())


class Tracer:
    def __init__(self):
        self._events = []
        self._lock = threading.Lock()
        self._step = 0

    def log(self, agent, action, detail="", reason=""):
        with self._lock:
            self._step += 1
            self._events.append(TraceEvent(self._step, agent, action, detail, reason))

    @property
    def events(self):
        return list(self._events)

    def to_json(self):
        return json.dumps([asdict(e) for e in self._events], indent=2)

    def save(self, path):
        Path(path).write_text(self.to_json(), encoding="utf-8")
