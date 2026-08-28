from __future__ import annotations

import threading
from collections import defaultdict
from dataclasses import dataclass
from time import perf_counter

_DURATION_BUCKETS = (0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0)


@dataclass(frozen=True, slots=True)
class Timer:
    started_at: float


class MetricsRegistry:
    """Dependency-free Prometheus registry for the control-plane trust boundary."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._counters: dict[tuple[str, tuple[tuple[str, str], ...]], float] = defaultdict(float)
        self._gauges: dict[tuple[str, tuple[tuple[str, str], ...]], float] = {}
        self._duration_sum: dict[tuple[str, tuple[tuple[str, str], ...]], float] = defaultdict(float)
        self._duration_count: dict[tuple[str, tuple[tuple[str, str], ...]], int] = defaultdict(int)
        self._duration_buckets: dict[
            tuple[str, tuple[tuple[str, str], ...], float], int
        ] = defaultdict(int)

    def inc(self, name: str, value: float = 1.0, **labels: str) -> None:
        key = (name, _labels(labels))
        with self._lock:
            self._counters[key] += value

    def set(self, name: str, value: float, **labels: str) -> None:
        key = (name, _labels(labels))
        with self._lock:
            self._gauges[key] = value

    def start_timer(self) -> Timer:
        return Timer(perf_counter())

    def observe_duration(self, name: str, timer: Timer, **labels: str) -> None:
        key = (name, _labels(labels))
        elapsed = max(0.0, perf_counter() - timer.started_at)
        with self._lock:
            self._duration_sum[key] += elapsed
            self._duration_count[key] += 1
            for boundary in _DURATION_BUCKETS:
                if elapsed <= boundary:
                    self._duration_buckets[(name, key[1], boundary)] += 1

    def render_prometheus(self) -> str:
        lines = [
            "# HELP ntshield_build_info NTAgentShield control-plane process information.",
            "# TYPE ntshield_build_info gauge",
            'ntshield_build_info{component="control-plane"} 1',
        ]
        with self._lock:
            emitted: set[str] = set()
            for (name, labels), value in sorted(self._counters.items()):
                metric = _metric_name(name)
                if metric not in emitted:
                    lines.append(f"# TYPE {metric} counter")
                    emitted.add(metric)
                lines.append(f"{metric}{_format_labels(labels)} {_format_number(value)}")
            for (name, labels), value in sorted(self._gauges.items()):
                metric = _metric_name(name)
                if metric not in emitted:
                    lines.append(f"# TYPE {metric} gauge")
                    emitted.add(metric)
                lines.append(f"{metric}{_format_labels(labels)} {_format_number(value)}")
            for (name, labels), value in sorted(self._duration_sum.items()):
                metric = _metric_name(name)
                if metric not in emitted:
                    lines.append(f"# TYPE {metric}_seconds histogram")
                    emitted.add(metric)
                for boundary in _DURATION_BUCKETS:
                    bucket_labels = tuple((*labels, ("le", _format_boundary(boundary))))
                    count = self._duration_buckets[(name, labels, boundary)]
                    lines.append(
                        f"{metric}_seconds_bucket{_format_labels(bucket_labels)} {count}"
                    )
                inf_labels = tuple((*labels, ("le", "+Inf")))
                count = self._duration_count[(name, labels)]
                lines.append(f"{metric}_seconds_bucket{_format_labels(inf_labels)} {count}")
                lines.append(
                    f"{metric}_seconds_sum{_format_labels(labels)} {_format_number(value)}"
                )
                lines.append(f"{metric}_seconds_count{_format_labels(labels)} {count}")
        return "\n".join(lines) + "\n"


def _labels(values: dict[str, str]) -> tuple[tuple[str, str], ...]:
    return tuple(sorted((key, str(value)) for key, value in values.items()))


def _metric_name(value: str) -> str:
    normalized = "".join(char if char.isalnum() or char == "_" else "_" for char in value)
    return normalized if normalized.startswith("ntshield_") else f"ntshield_{normalized}"


def _format_labels(labels: tuple[tuple[str, str], ...]) -> str:
    if not labels:
        return ""
    encoded = ",".join(f'{key}="{_escape(value)}"' for key, value in sorted(labels))
    return "{" + encoded + "}"


def _escape(value: str) -> str:
    return value.replace("\\", "\\\\").replace("\n", "\\n").replace('"', '\\"')


def _format_number(value: float) -> str:
    return str(int(value)) if value.is_integer() else format(value, ".12g")


def _format_boundary(value: float) -> str:
    return str(int(value)) if value.is_integer() else format(value, "g")
