"""Structured logging and a dependency-free Prometheus metrics registry.

No third-party metrics client is required (keeps the air-gapped install lean).
The registry renders the Prometheus text exposition format directly, so a stock
Prometheus/Grafana stack can scrape ``/metrics`` out of the box.
"""
from __future__ import annotations

import json
import logging
import os
import sys
import threading
import time
import uuid

_LATENCY_BUCKETS = (0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30, 60)


def new_request_id() -> str:
    return uuid.uuid4().hex


def _labels_key(labels: dict[str, str] | None) -> tuple[tuple[str, str], ...]:
    return tuple(sorted((labels or {}).items()))


def _fmt_labels(key: tuple[tuple[str, str], ...]) -> str:
    if not key:
        return ""
    inner = ",".join(f'{k}="{str(v)}"' for k, v in key)
    return "{" + inner + "}"


class Metrics:
    """Minimal counter + histogram registry with Prometheus rendering."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._counters: dict[str, dict[tuple, float]] = {}
        self._hist: dict[str, dict[tuple, dict]] = {}
        self._help: dict[str, str] = {}

    def counter(self, name: str, help_text: str = "") -> None:
        self._help.setdefault(name, help_text)
        self._counters.setdefault(name, {})

    def inc(self, name: str, labels: dict[str, str] | None = None, value: float = 1.0) -> None:
        with self._lock:
            self._counters.setdefault(name, {})
            k = _labels_key(labels)
            self._counters[name][k] = self._counters[name].get(k, 0.0) + value

    def histogram(self, name: str, help_text: str = "") -> None:
        self._help.setdefault(name, help_text)
        self._hist.setdefault(name, {})

    def observe(self, name: str, value: float, labels: dict[str, str] | None = None) -> None:
        with self._lock:
            self._hist.setdefault(name, {})
            k = _labels_key(labels)
            slot = self._hist[name].setdefault(
                k, {"count": 0, "sum": 0.0, "buckets": {b: 0 for b in _LATENCY_BUCKETS}})
            slot["count"] += 1
            slot["sum"] += value
            for b in _LATENCY_BUCKETS:
                if value <= b:
                    slot["buckets"][b] += 1

    def render(self) -> str:
        lines = []
        with self._lock:
            for name, series in self._counters.items():
                if self._help.get(name):
                    lines.append(f"# HELP {name} {self._help[name]}")
                lines.append(f"# TYPE {name} counter")
                if not series:
                    lines.append(f"{name} 0")
                for k, v in series.items():
                    lines.append(f"{name}{_fmt_labels(k)} {v}")
            for name, series in self._hist.items():
                if self._help.get(name):
                    lines.append(f"# HELP {name} {self._help[name]}")
                lines.append(f"# TYPE {name} histogram")
                for k, slot in series.items():
                    base = dict(k)
                    cum = 0
                    for b in _LATENCY_BUCKETS:
                        cum = slot["buckets"][b]
                        lk = _labels_key({**base, "le": str(b)})
                        lines.append(f"{name}_bucket{_fmt_labels(lk)} {cum}")
                    lk_inf = _labels_key({**base, "le": "+Inf"})
                    lines.append(f"{name}_bucket{_fmt_labels(lk_inf)} {slot['count']}")
                    lines.append(f"{name}_sum{_fmt_labels(k)} {slot['sum']}")
                    lines.append(f"{name}_count{_fmt_labels(k)} {slot['count']}")
        return "\n".join(lines) + "\n"


metrics = Metrics()
metrics.counter("codesentinel_scans_total", "Total scans processed")
metrics.counter("codesentinel_findings_total", "Total findings emitted by severity")
metrics.counter("codesentinel_auth_failures_total", "Authentication failures")
metrics.histogram("codesentinel_scan_duration_seconds", "Scan duration in seconds")


class _JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(record.created)),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        }
        for attr in ("request_id", "tenant", "path", "status", "duration_ms"):
            if hasattr(record, attr):
                payload[attr] = getattr(record, attr)
        if record.exc_info:
            payload["exc"] = self.formatException(record.exc_info)
        return json.dumps(payload)


def configure_logging(fmt: str | None = None, level: str = "INFO") -> None:
    fmt = fmt or os.getenv("CODESENTINEL_LOG_FORMAT", "json")
    handler = logging.StreamHandler(sys.stdout)
    if fmt == "json":
        handler.setFormatter(_JsonFormatter())
    else:
        handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s %(message)s"))
    root = logging.getLogger()
    root.handlers = [handler]
    root.setLevel(getattr(logging, level.upper(), logging.INFO))
