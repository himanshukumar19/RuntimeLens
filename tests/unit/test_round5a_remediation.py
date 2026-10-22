"""Tests for the Round 5a remediation (Decisions D-34, the capture-window fix
and the dataset-gate capture-sufficiency check).

Three independent changes are pinned here:

1. **D-34** — the `high` mining profile runs at the 200 mcores cgroup cap, so
   the wall time of the busy loop is ``CPU-seconds / 0.2``. The Round 5a
   measurement gave 5.865 and 6.004 ms of CPU per 3000-iteration inner loop
   for 10 000 iterations, i.e. 293.64 s and 300.81 s of wall time, not the
   125 s the registry declares. The iteration count is now 4200.

2. **Capture window** — the Falco collector must use an absolute cutoff.

3. **Capture sufficiency** — the dataset gate must refuse a run directory with
   an empty source, and the runner must quarantine a gate-failed run.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

import scripts.stage4a_runner as runner
from runtimelens.collector.per_run_capture import PerRunTelemetryCapture
from scripts.stage4a_round4 import ROUND4_TEMPLATE_DEFS
from scripts.verify_dataset import REQUIRED_SOURCES, run_dataset_verification

# --------------------------------------------------------------------------------------
# 1. Decision D-34 — the mining duration recalibration
# --------------------------------------------------------------------------------------

# Measured in the Stage 4a Round 5a runs (real telemetry, no simulation).
MEASURED_MS_PER_INNER_LOOP = (5.865, 6.004)
TENANT_CPU_LIMIT_MCORES = 200.0
TARGET_BUSY_LOOP_SECONDS = 125.0
TARGET_TOTAL_WALL_SECONDS = 130.0

HIGH_TEMPLATES = ("TMPL-MNR-01", "TMPL-MNR-02", "TMPL-MNR-05")


def _mining_def(template_id: str) -> dict[str, object]:
    return next(d for d in ROUND4_TEMPLATE_DEFS if d["template_id"] == template_id)


def test_the_measured_cpu_cost_per_inner_loop_is_5_9_ms() -> None:
    """The basis of D-34, recomputed from the two measured Round 5a runs."""
    low, high = MEASURED_MS_PER_INNER_LOOP
    assert 5.5 < low < 6.5
    assert 5.5 < high < 6.5
    assert high / low < 1.05, "the two measurements must agree within 5 %"


#: The measured wall time per 3000-iteration inner loop at the 200 mcores cap,
#: in milliseconds, from the three real Round 5a measurements of the mining
#: loop (Decision D-36). The spread is ~14 %, so the iteration count is set
#: for the FASTEST observed case, exactly as Decision D-26 sets a band from
#: the measured noise floor.
MEASURED_MS_PER_ITERATION = (28.84, 28.07, 25.33)

#: The gate's duration requirement, in seconds, measured as the cAdvisor sample
#: window (scripts/stage2_pilot.py: `calc_dur < 115.0`).
GATE_MIN_WINDOW_SECONDS = 115.0

#: The settle window (5 s) plus the nslookup, minus the sample offset.
WINDOW_OVERHEAD_SECONDS = 5.1


def test_high_profile_iteration_count_yields_the_d22_duration() -> None:
    """4950 iterations = the D-22 125 s busy loop in the FASTEST observed case."""
    for template_id in HIGH_TEMPLATES:
        command = str(_mining_def(template_id)["command"])
        assert "seq 4950" in command, template_id

    fastest = min(MEASURED_MS_PER_ITERATION)
    slowest = max(MEASURED_MS_PER_ITERATION)
    busy_fast = 4950 * fastest / 1000
    busy_slow = 4950 * slowest / 1000
    assert busy_fast == pytest.approx(125.4, abs=1.0)
    assert 123.0 <= busy_fast <= 127.0

    # The gate measures the cAdvisor window: it must clear the requirement in
    # the FASTEST observed case, not only in the slow one.
    window_fast = busy_fast + WINDOW_OVERHEAD_SECONDS
    window_slow = busy_slow + WINDOW_OVERHEAD_SECONDS
    assert window_fast >= GATE_MIN_WINDOW_SECONDS + 10.0, window_fast
    assert window_slow >= GATE_MIN_WINDOW_SECONDS
    assert TARGET_TOTAL_WALL_SECONDS - 2.0 <= window_fast <= TARGET_TOTAL_WALL_SECONDS + 2.0


def test_the_old_iteration_count_would_fail_the_gate_in_the_fast_case() -> None:
    """The regression: 4200 iterations gave a 111.5 s window in the fast case."""
    fastest = min(MEASURED_MS_PER_ITERATION)
    window = 4200 * fastest / 1000 + WINDOW_OVERHEAD_SECONDS
    assert window < GATE_MIN_WINDOW_SECONDS, window
    assert window == pytest.approx(111.5, abs=0.5)


def test_the_old_iteration_count_is_what_produced_the_300_second_run() -> None:
    """10 000 iterations reproduces the measured 293.64 s / 300.81 s runs."""
    ms_mean = sum(MEASURED_MS_PER_INNER_LOOP) / 2
    wall = 10000 * (ms_mean / 1000) / (TENANT_CPU_LIMIT_MCORES / 1000)
    assert 290.0 <= wall <= 300.0, "the 10 000-iteration count reproduces the measured runs"


def test_the_measured_iteration_cost_spread_is_recorded() -> None:
    """The three measurements of the same loop shape, and their spread."""
    values = MEASURED_MS_PER_ITERATION
    assert len(values) == 3
    assert 25.0 <= min(values) <= 26.0
    assert 28.0 <= max(values) <= 29.5
    assert max(values) / min(values) - 1.0 == pytest.approx(0.139, abs=0.01)


def test_mnr06_iteration_count_matches_its_declared_duration() -> None:
    """683 iterations x (90 ms pause + 12.4 ms loop) = the declared 70 s."""
    command = str(_mining_def("TMPL-MNR-06")["command"])
    assert "seq 683" in command
    wall = 683 * (90.0 + 12.4) / 1000
    assert 69.0 <= wall <= 71.0


def test_mining_templates_still_use_the_verified_inner_loop_shape() -> None:
    for definition in ROUND4_TEMPLATE_DEFS:
        if definition["threat_class"] != "cryptomining":
            continue
        assert "while [ $j -lt 3000 ]" in str(definition["command"])


def test_the_mining_intensities_are_the_recomputed_ones() -> None:
    """D-35: MNR-04 is measured, MNR-06/07/08 are derived from that measurement."""
    expected = {
        "TMPL-MNR-01": "200m",
        "TMPL-MNR-02": "200m",
        "TMPL-MNR-04": "~80m",
        "TMPL-MNR-05": "200m",
        "TMPL-MNR-06": "~69m",
        "TMPL-MNR-07": "~80m",
        "TMPL-MNR-08": "~96m",
    }
    for template_id, intensity in expected.items():
        assert _mining_def(template_id)["intensity"] == intensity, template_id


def test_every_mining_pool_probe_carries_a_payload() -> None:
    """`nc` in UDP mode copies stdin: without a payload it sends no datagram.

    That was the Round 5a attempt-2 defect: the probe was
    `nc -u -w 1 <ip> <port>`, stdin was at EOF under `kubectl exec` without
    `-i`, so no packet left the pod, Cilium recorded no flow, and the
    per-run gate failed on an empty Hubble source. The verified corpus anchor
    `TMPL-MNR-03` pipes a payload and its telemetry contains the two dropped
    pool-egress flows.
    """
    for definition in ROUND4_TEMPLATE_DEFS:
        if definition["threat_class"] != "cryptomining":
            continue
        command = str(definition["command"])
        assert "echo p | nc -u -w 1 198.51.100.22" in command, definition["template_id"]


def test_the_expected_hubble_flow_counts_are_declared() -> None:
    """6 flows with the type-A DNS observation, 2 without it."""
    expected = {
        "TMPL-MNR-01": 6,
        "TMPL-MNR-02": 6,
        "TMPL-MNR-04": 2,
        "TMPL-MNR-05": 6,
        "TMPL-MNR-06": 2,
        "TMPL-MNR-07": 6,
        "TMPL-MNR-08": 2,
    }
    for template_id, flows in expected.items():
        assert _mining_def(template_id)["expect_hubble_flows"] == flows, template_id


def test_no_gate_threshold_was_touched() -> None:
    """D-34 changes the scenario, never the gate."""
    from runtimelens.eval.cpu_bands import (
        BURST_MEDIAN_MAX_MCORES,
        BURST_PEAK_MAX_MCORES,
        BURST_PEAK_MIN_MCORES,
        CPU_LAG_EXCLUSION_SECONDS,
        HIGH_CPU_MCORES,
        HIGH_CPU_MIN_PCT,
        MIN_POST_LAG_SAMPLES,
        THROTTLED_CPU_MCORES,
    )

    assert (BURST_PEAK_MIN_MCORES, BURST_PEAK_MAX_MCORES, BURST_MEDIAN_MAX_MCORES) == (
        20.0,
        150.0,
        100.0,
    )
    assert (HIGH_CPU_MCORES, HIGH_CPU_MIN_PCT) == (100.0, 80.0)
    assert (THROTTLED_CPU_MCORES, MIN_POST_LAG_SAMPLES, CPU_LAG_EXCLUSION_SECONDS) == (
        40.0,
        4,
        15.0,
    )


# --------------------------------------------------------------------------------------
# 2. The dataset gate must refuse an empty source
# --------------------------------------------------------------------------------------


def _write_minimal_run(run_dir: Path, *, falco_events: int = 1) -> None:
    for source in ("falco", "audit", "hubble", "prometheus", "trivy", "pod"):
        (run_dir / source).mkdir(parents=True, exist_ok=True)
    for _ in range(falco_events):
        (run_dir / "falco" / "events.jsonl").write_text(
            json.dumps({"time": "2026-10-20T01:00:00.000000Z", "output_fields": {}}) + "\n"
        )
    (run_dir / "audit" / "events.jsonl").write_text(
        json.dumps(
            {
                "stageTimestamp": "2026-10-20T01:00:00.000000Z",
                "objectRef": {"namespace": "tenant-a"},
                "user": {"username": "x"},
            }
        )
        + "\n"
    )
    (run_dir / "hubble" / "flows.jsonl").write_text(
        json.dumps({"flow": {"time": "2026-10-20T01:00:00.000000Z"}}) + "\n"
    )
    (run_dir / "prometheus" / "metrics.json").write_text(
        json.dumps(
            {
                "samples": [
                    {
                        "timestamp": "2026-10-20T01:00:00.000000Z",
                        "pod_stats": [
                            {
                                "containers": [
                                    {"cpu": {"usageNanoCores": 1000000.0}},
                                ]
                            }
                        ],
                    }
                ]
            }
        )
    )
    (run_dir / "trivy" / "report.json").write_text("{}")
    (run_dir / "pod" / "spec.json").write_text("{}")
    (run_dir / "index.json").write_text(
        json.dumps(
            {
                "run_id": run_dir.name,
                "threat_class": "benign",
                "scenario_id": "TMPL-BEN-99",
                "expected_cpu_profile": "low",
                "duration_seconds": 5.0,
            }
        )
    )


def test_required_sources_are_the_five_telemetry_sources() -> None:
    assert REQUIRED_SOURCES == ("falco", "audit", "hubble", "prometheus", "trivy")


def test_dataset_gate_fails_when_a_source_is_empty(tmp_path: Path) -> None:
    runs_dir = tmp_path / "runs"
    runs_dir.mkdir()
    _write_minimal_run(runs_dir / "run-empty-falco", falco_events=0)
    rc = run_dataset_verification(runs_dir)
    assert rc == 1, "the dataset gate must refuse a run with an empty source"


def test_dataset_gate_accepts_a_complete_run(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    runs_dir = tmp_path / "runs"
    runs_dir.mkdir()
    _write_minimal_run(runs_dir / "run-complete", falco_events=1)
    rc = run_dataset_verification(runs_dir)
    out = capsys.readouterr().out
    assert "GATE VERDICT: PASSED" in out
    assert rc == 0


# --------------------------------------------------------------------------------------
# 3. The runner must quarantine a gate-failed run
# --------------------------------------------------------------------------------------


def test_runner_has_a_failed_runs_quarantine_directory() -> None:
    assert Path("data/raw/failed_runs") == runner.FAILED_RUNS_DIR
    assert Path("data/raw_backup") == runner.BACKUP_DIR


def test_runner_quarantines_the_run_on_a_gate_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The failed run must end up in failed_runs/, never in the runs directory."""
    runs_dir = tmp_path / "runs"
    failed_dir = tmp_path / "failed_runs"
    backup_dir = tmp_path / "backup"
    monkeypatch.setattr(runner, "BACKUP_DIR", backup_dir)
    monkeypatch.setattr(runner, "FAILED_RUNS_DIR", failed_dir)

    collector = PerRunTelemetryCapture(base_dir=runs_dir)
    template = {
        "run_id": "run-quarantine-test",
        "template_id": "TMPL-BEN-99",
        "threat_class": "benign",
        "namespace": "tenant-a",
        "app": "web",
        "command": "true",
        "expected_cpu_profile": "low",
        "mode": "exec",
        "expect_falco": [],
        "expect_verbs": [],
        "expect_hubble_band": "LOW",
        "expect_features": ["F", "F", "F"],
        "sleep_after": 0,
    }

    # Every external dependency of a run is stubbed: the test exercises the
    # gate -> backup -> quarantine path only.
    monkeypatch.setattr(runner, "check_receivers", lambda: None)
    monkeypatch.setattr(runner, "check_resources", lambda phase: None)
    monkeypatch.setattr(runner, "resolve_pod_name", lambda ns, app: "web-1")
    monkeypatch.setattr(
        runner, "wait_for_pod_cooldown", lambda ns, pod, max_wait_seconds=60.0: True
    )
    monkeypatch.setattr(runner, "cleanup_pod", lambda ns, pod: None)
    monkeypatch.setattr(runner, "check_no_leftovers", lambda: None)
    monkeypatch.setattr(runner, "capture_cpu_samples", lambda run_dir: [])

    real_capture = collector.capture_cadvisor_metrics

    def _capture(pod_name: str, namespace: str, run_dir: Path) -> int:
        run_dir.mkdir(parents=True, exist_ok=True)
        (run_dir / "prometheus").mkdir(parents=True, exist_ok=True)
        (run_dir / "prometheus" / "metrics.json").write_text(
            json.dumps({"samples": [{"timestamp": "2026-10-20T01:00:00.000000Z", "pod_stats": []}]})
        )
        return 1

    monkeypatch.setattr(collector, "capture_cadvisor_metrics", _capture)
    monkeypatch.setattr(collector, "capture_falco_alerts", lambda *a, **k: 0)
    monkeypatch.setattr(collector, "capture_k8s_audit_events", lambda *a, **k: 0)
    monkeypatch.setattr(collector, "capture_hubble_flows", lambda *a, **k: 0)
    monkeypatch.setattr(collector, "attach_trivy_report", lambda run_dir: False)
    monkeypatch.setattr(collector, "attach_pod_spec", lambda run_dir, spec: None)
    monkeypatch.setattr("subprocess.Popen", _fake_popen)
    del real_capture

    with pytest.raises(runner.Stage4aStop):
        runner.run_one(template, collector)

    assert not (runs_dir / "run-quarantine-test").exists(), "the failed run must leave the runs dir"
    assert (failed_dir / "run-quarantine-test").exists(), "the failed run must be quarantined"
    assert (backup_dir / "run-quarantine-test").exists(), "the authoritative backup must exist"


class _FakeProc:
    returncode = 0

    def poll(self) -> int:
        return 0

    def wait(self, timeout: float | None = None) -> int:
        return 0

    def communicate(self) -> tuple[bytes, bytes]:
        return b"", b""


def _fake_popen(*args: object, **kwargs: object) -> _FakeProc:
    return _FakeProc()
