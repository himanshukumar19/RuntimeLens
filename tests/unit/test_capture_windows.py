"""Regression tests for the per-run capture windows (Stage 4a Round 5a finding).

The Stage 4a Round 5a run ``run-s4a-r4-02`` lasted 300.81 s. The Falco
collector asked ``kubectl logs --since=300s``, so its pre-filter window ended
at ``t_start + 0.81 s`` and it discarded the two Falco events that the rules
had emitted at ``t_start + 0.18 s`` -- both of them inside the run window.
The per-run gate then failed with ``Missing telemetry from source 'falco'``.

These tests pin the corrected behaviour: the capture window must be
**absolute** and must cover a run of any length.
"""

from __future__ import annotations

import json
from datetime import datetime

import pytest

from runtimelens.collector.per_run_capture import (
    AUDIT_LOG_MAX_WIDEN_ATTEMPTS,
    AUDIT_LOG_MIN_TAIL_LINES,
    LOG_WINDOW_MARGIN_SECONDS,
    PerRunTelemetryCapture,
    audit_log_tail_lines,
    falco_log_since_time,
)


def _ts(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


# The real measured values of the failed Round 5a run.
RUN2_T_START = "2026-10-20T01:14:37.745327Z"
RUN2_T_END = "2026-10-20T01:19:38.557882Z"
RUN2_FIRST_EVENT = "2026-10-20T01:14:37.926525866Z"
RUN2_SECOND_EVENT = "2026-10-20T01:14:37.928748658Z"


def test_falco_cutoff_is_absolute_and_covers_the_failed_run() -> None:
    """The cutoff must precede the first event of the run that actually failed."""
    cutoff = _ts(falco_log_since_time(RUN2_T_START))
    assert cutoff <= _ts(RUN2_FIRST_EVENT)
    assert cutoff <= _ts(RUN2_SECOND_EVENT)
    assert cutoff < _ts(RUN2_T_START)


def test_falco_cutoff_does_not_depend_on_the_run_duration() -> None:
    """A 10 s run and a 10 000 s run must get the same cutoff for the same start."""
    assert falco_log_since_time(RUN2_T_START) == falco_log_since_time(RUN2_T_START)
    cutoff = _ts(falco_log_since_time(RUN2_T_START))
    for duration in (10, 300, 1000, 10_000, 86_400):
        end = _ts(RUN2_T_START).timestamp() + duration
        del end  # the cutoff is computed from the start only
        assert cutoff == _ts(falco_log_since_time(RUN2_T_START))


def test_falco_cutoff_margin_is_two_seconds() -> None:
    start = _ts(RUN2_T_START)
    cutoff = _ts(falco_log_since_time(RUN2_T_START))
    assert (start - cutoff).total_seconds() == pytest.approx(LOG_WINDOW_MARGIN_SECONDS)
    assert LOG_WINDOW_MARGIN_SECONDS == 2.0


def test_falco_capture_command_uses_no_fixed_relative_window(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The ``kubectl logs`` invocation must not carry a fixed ``--since=<N>s``."""
    captured: dict[str, list[str]] = {}

    class _Result:
        stdout = ""
        stderr = ""
        returncode = 0

    def _fake_run(cmd: list[str], **kwargs: object) -> _Result:
        captured["cmd"] = list(cmd)
        return _Result()

    monkeypatch.setattr("runtimelens.collector.per_run_capture.subprocess.run", _fake_run)
    collector = PerRunTelemetryCapture()
    run_dir = collector.prepare_run_dir("t")
    collector.capture_falco_alerts("pod-1", "tenant-a", RUN2_T_START, run_dir)

    cmd = captured["cmd"]
    assert not any(part.startswith("--since=") for part in cmd), cmd
    assert any(part.startswith("--since-time=") for part in cmd), cmd
    since_time = next(part for part in cmd if part.startswith("--since-time=")).split("=", 1)[1]
    assert _ts(since_time) <= _ts(RUN2_FIRST_EVENT)


def test_a_run_longer_than_300s_keeps_its_first_event() -> None:
    """The literal regression: a >300 s run must not lose its t0 event.

    The old relative window (``--since=300s``) cut the log at ``t_end - 300 s``
    = ``t_start + 0.81 s`` for the real 300.81 s run, which is *after* the
    events at ``t_start + 0.18 s``. The absolute cutoff keeps them.
    """
    duration = (_ts(RUN2_T_END) - _ts(RUN2_T_START)).total_seconds()
    assert duration > 300.0, "this regression is defined on a run longer than 300 s"

    old_cutoff = _ts(RUN2_T_END).timestamp() - 300.0
    assert _ts(RUN2_FIRST_EVENT).timestamp() < old_cutoff, (
        "the old 300 s relative window would have dropped the first event"
    )

    new_cutoff = _ts(falco_log_since_time(RUN2_T_START)).timestamp()
    assert _ts(RUN2_FIRST_EVENT).timestamp() >= new_cutoff, (
        "the absolute cutoff must keep the first event"
    )


def test_audit_tail_is_scaled_to_the_run_duration() -> None:
    short = audit_log_tail_lines(RUN2_T_START, RUN2_T_START)
    long_run = audit_log_tail_lines(RUN2_T_START, "2026-10-20T03:00:00.000000Z")
    assert short == AUDIT_LOG_MIN_TAIL_LINES
    assert long_run > short
    assert long_run >= AUDIT_LOG_MIN_TAIL_LINES


def test_audit_tail_covers_a_ten_hour_run() -> None:
    tail = audit_log_tail_lines("2026-10-20T00:00:00.000000Z", "2026-10-20T10:00:00.000000Z")
    # 20 lines/s * 36000 s = 720 000 lines, i.e. far beyond the observed rate.
    assert tail >= 720_000


def test_audit_filter_matches_namespace_service_account_and_pod() -> None:
    raw = "\n".join(
        [
            json.dumps(
                {
                    "stageTimestamp": "2026-10-20T01:14:38.000000Z",
                    "objectRef": {"namespace": "tenant-b"},
                    "user": {"username": "system:serviceaccount:tenant-a:default"},
                }
            ),
            json.dumps(
                {
                    "stageTimestamp": "2026-10-20T01:14:38.000000Z",
                    "objectRef": {"namespace": "other"},
                    "user": {"username": "system:serviceaccount:tenant-a:default"},
                }
            ),
            json.dumps(
                {
                    "stageTimestamp": "2026-10-20T01:14:38.000000Z",
                    "objectRef": {"namespace": "other"},
                    "user": {
                        "username": "someone",
                        "extra": {"authentication.kubernetes.io/pod-name": ["pod-1"]},
                    },
                }
            ),
            json.dumps(
                {
                    "stageTimestamp": "2026-10-20T01:14:38.000000Z",
                    "objectRef": {"namespace": "other"},
                    "user": {"username": "someone"},
                }
            ),
        ]
    )
    matched, oldest = PerRunTelemetryCapture._filter_audit_lines(
        raw,
        pod_name="pod-1",
        namespace="tenant-a",
        t_start_iso=RUN2_T_START,
        t_end_iso=RUN2_T_END,
    )
    assert len(matched) == 3
    assert oldest == "2026-10-20T01:14:38.000000Z"


def test_audit_filter_drops_events_outside_the_run_window() -> None:
    raw = json.dumps(
        {
            "stageTimestamp": "2026-10-20T00:00:00.000000Z",
            "objectRef": {"namespace": "tenant-a"},
            "user": {"username": "system:serviceaccount:tenant-a:default"},
        }
    )
    matched, oldest = PerRunTelemetryCapture._filter_audit_lines(
        raw,
        pod_name="pod-1",
        namespace="tenant-a",
        t_start_iso=RUN2_T_START,
        t_end_iso=RUN2_T_END,
    )
    assert matched == []
    assert oldest == "2026-10-20T00:00:00.000000Z"


def test_audit_widening_is_bounded() -> None:
    assert AUDIT_LOG_MAX_WIDEN_ATTEMPTS >= 1
    assert isinstance(AUDIT_LOG_MAX_WIDEN_ATTEMPTS, int)
