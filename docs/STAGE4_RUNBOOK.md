# STAGE4_RUNBOOK.md — Stage 4 Execution Runbook (offline draft, nothing frozen)

> **Status:** DRAFT for teammate review. Nothing is frozen. No gate is marked passed by this document.
> **Scope of this file:** it specifies *how* Stage 4a (smoke) and Stage 4b (full 400) will be executed. It does not authorize execution.
> **Prohibitions honoured while writing this file:** no `git push`, no `sudo`, no `multipass stop/start/restart`, no test-split access, no `SCALEDOWN_API_KEY` usage, no cluster mutation. The only cluster interaction was read-only (`helm list`, `kubectl logs`, `kubectl exec … grep` on a rules file) as explicitly permitted.
> **Class scope (Decision D-24):** `container_escape`, `privilege_abuse`, `cryptomining` + `benign` + `unknown`. `exfiltration` is **not** an attack class; the 5 historical exfil pilot runs stay in the dataset marked `"pilot only, class dropped"`.

---

## 0. Evidence base for every number in this runbook

Every timing figure below is either (a) **measured** from committed/collected pilot data, with the exact command shown, or (b) explicitly marked **estimate**. Nothing else is stated as fact.

| Quantity | Value | Provenance |
|:---|:---|:---|
| Templates in the plan | **55** (benign 21, escape 10, privilege 8, mining 8, unknown 8) | parsed from `docs/SCENARIO_PLAN_v2.md` table rows |
| Planned runs | **400** (140/80/80/60/40) | parsed from the same table |
| Per-run wall clock, benign | 7.13 – 9.15 s (one cpu-burst run 25.32 s) | `data/raw/runs/*/index.json` → `duration_seconds` (n=5) |
| Per-run wall clock, container_escape | 7.12 – 7.15 s | same source (n=5) |
| Per-run wall clock, privilege_abuse | 7.11 – 9.15 s | same source (n=5) |
| Per-run wall clock, cryptomining | 124.23 – 130.29 s | same source (n=5) |
| Per-run wall clock, exfiltration (dropped class, retained) | 9.13 – 9.14 s | same source (n=5) |
| Pilot 5-source capture completeness | 5/5 sources present in every run dir (`falco/ audit/ hubble/ prometheus/ trivy/`) | `ls data/raw/runs/run-test-01-prv/` |
| Per-run wall clock == capture window | 9 of 10 pilot runs have `index.json duration_seconds` **identical** to the harness `elapsed_seconds` in `data/scenarios/pilot_25_metrics.json` | pair-compared; one mismatch (`run-p06-mnr`: 130.13 vs 124.24) |
| Receiver ports | Hubble relay 4245, Falco webhook 8765, Audit webhook 8766 | `scripts/stage2_pilot.py:57-61` |
| Resource stop thresholds | RAM available < 2048 MB; disk ≥ 80 % | `scripts/stage2_pilot.py:64-88`, enforced at `scripts/stage2_pilot.py:711-713` and `:749-753` |

---

## 1. Prerequisites — all must be satisfied and recorded before Stage 4a starts

### P1. Linter edit for the `etc` hostPath — **APPLIED**

`TMPL-ESC-04` and `TMPL-ESC-09` mount `/opt/runtimelens-dummy/etc` as a `hostPath` of type `Directory`. The safety linter previously rejected it.

Code at `scripts/scenario_safety_lint.py:21-29` (as applied):

```python
ALLOWED_DUMMY_HOSTPATHS: Final[frozenset[str]] = frozenset(
    {
        "/opt/runtimelens-dummy/docker.sock",
        "/opt/runtimelens-dummy/containerd.sock",
        # Inert dummy DIRECTORY (type: Directory) for TMPL-ESC-04 / TMPL-ESC-09.
        # Never a real host path: contains no host state, no credentials, no runtime socket.
        "/opt/runtimelens-dummy/etc",
    }
)
```

**No other linter rule was changed.** The following remain enforced unchanged and are covered by regression tests in `tests/unit/test_scenario_safety_lint.py`:

| Linter rule | Location | Effect | Regression test |
|:---|:---|:---|:---|
| `hostPath` only in `sandbox-workloads` | `scripts/scenario_safety_lint.py:19`, `:130-135` | tenant namespaces can never mount a host path | `test_safety_lint_fails_on_hostpath_in_tenant_namespace` |
| `hostPID` / `hostNetwork` / `hostIPC: true` unconditionally forbidden | `:102-107` | this is why `TMPL-ESC-07` uses `readlink` on the container's own `/proc/1/root` instead of a host-PID pod | `test_safety_lint_still_fails_on_hostpid_in_lab_namespace` |
| real runtime sockets forbidden | `:28-34`, `:116-120` | `/var/run/docker.sock`, `/run/containerd`, `/var/run/containerd`, `/var/run/crio`, `/run/crio` | `test_safety_lint_fails_on_real_runtime_socket_mount` |
| `privileged: true` only in `sandbox-workloads` | `:146-150` | `TMPL-ESC-06`, `-08`, `-10` are sandbox-only | `test_safety_lint_fails_on_privileged_outside_lab_namespace` |
| class-leak tokens in names/labels | `:36-76`, `:141-142` | no `SC-*`, no class name, in any resource name | `test_safety_lint_fails_on_class_leak_in_name` |
| real host paths still rejected after widening the allowlist | `:123-127` | `/etc/kubernetes` is **not** accepted | `test_safety_lint_still_fails_on_real_kubernetes_hostpath` |

**Verification performed (offline, 3 manifest cases):** a manifest mounting `/opt/runtimelens-dummy/etc` in `sandbox-workloads` PASSes; a manifest mounting `/etc/kubernetes` in `sandbox-workloads` FAILS with `hostPath outside dummy allowlist`; a manifest with `hostPID: true` in `sandbox-workloads` FAILS with `Forbidden hostPID: true`. All three are now permanent unit tests (16 passed).

> Note: the linter's class-leak token list includes `esc`, `prv` and `mnr`, so a *cluster resource* may not be named after a template id. Template ids are documentation identifiers only; live resource names must be leak-free.

### P1b. Inert dummy identity files for `TMPL-ESC-09` — **PROVISIONING STEP, NOT YET EXECUTED**

`TMPL-ESC-09` performs a *multi-file* read (`head`, `dd` and `find`) over the mounted dummy `/etc` directory, and `TMPL-ESC-10` mounts the third allowlisted dummy path `/opt/runtimelens-dummy/containerd.sock`. Both require node-side files that do not exist yet.

The files are **inert, 0-byte and completely empty**. They carry no real user, group, host or credential data of any kind; they exist only so that the multi-file read produces real filesystem telemetry and so that the `Read Sensitive Host Information Untrusted` rule can fire on the dummy path `/opt/runtimelens-dummy/etc/shadow`.

| Dummy path (name only) | Size | Mode | Used by |
|:---|--:|:---:|:---|
| `/opt/runtimelens-dummy/docker.sock` | 0 bytes | `0644` | `TMPL-ESC-03` (already provisioned) |
| `/opt/runtimelens-dummy/containerd.sock` | 0 bytes | `0644` | `TMPL-ESC-10` (replaced) |
| `/opt/runtimelens-dummy/etc/shadow` | 0 bytes | `0640` | `TMPL-ESC-04`, `TMPL-ESC-09` (already provisioned) |
| `/opt/runtimelens-dummy/etc/passwd` | 0 bytes | `0644` | `TMPL-ESC-09` (new) |
| `/opt/runtimelens-dummy/etc/group` | 0 bytes | `0644` | `TMPL-ESC-09` (new) |
| `/opt/runtimelens-dummy/etc/hosts` | 0 bytes | `0644` | `TMPL-ESC-09` (new) |

Provisioning commands (run **inside the kind control-plane node only**; nothing is created on the VM host or anywhere outside `/opt/runtimelens-dummy/`):

```bash
docker exec runtimelens-control-plane mkdir -p /opt/runtimelens-dummy
docker exec runtimelens-control-plane touch /opt/runtimelens-dummy/docker.sock
docker exec runtimelens-control-plane chmod 0644 /opt/runtimelens-dummy/docker.sock
docker exec runtimelens-control-plane touch /opt/runtimelens-dummy/containerd.sock
docker exec runtimelens-control-plane chmod 0644 /opt/runtimelens-dummy/containerd.sock
docker exec runtimelens-control-plane mkdir -p /opt/runtimelens-dummy/etc
docker exec runtimelens-control-plane touch /opt/runtimelens-dummy/etc/shadow
docker exec runtimelens-control-plane chmod 0640 /opt/runtimelens-dummy/etc/shadow
docker exec runtimelens-control-plane touch /opt/runtimelens-dummy/etc/passwd
docker exec runtimelens-control-plane chmod 0644 /opt/runtimelens-dummy/etc/passwd
docker exec runtimelens-control-plane touch /opt/runtimelens-dummy/etc/group
docker exec runtimelens-control-plane chmod 0644 /opt/runtimelens-dummy/etc/group
docker exec runtimelens-control-plane touch /opt/runtimelens-dummy/etc/hosts
docker exec runtimelens-control-plane chmod 0644 /opt/runtimelens-dummy/etc/hosts
```

Verification (read-only, must be pasted into the Round 2 evidence):

```bash
docker exec runtimelens-control-plane ls -la /opt/runtimelens-dummy /opt/runtimelens-dummy/etc
```

Invariants: no file is created outside `/opt/runtimelens-dummy/`; every file is 0 bytes; no file is a socket, device node or symlink; the `etc` directory is mounted with `hostPath` **type `Directory`** and the two socket proxies with **type `File`**.

### P2. `expected_cpu_profile` present in `index.json`

Already implemented end-to-end:

- written by `src/runtimelens/collector/per_run_capture.py:285` (parameter) and `:296` (serialised into `index.json`);
- read by `scripts/verify_dataset.py:158` and `:268`;
- passed by `scripts/stage2_pilot.py:778`, `:789`, `:851`;
- consumed by the variant-aware gate in `scripts/verify_dataset.py:270-299` (`high` / `throttled` / `burst` / `low`).

**Gap to close:** all 25 existing pilot `index.json` files were written **before** this field existed and therefore do not contain it (`grep -c expected_cpu_profile` = 0 for every file). `scripts/verify_dataset.py:158-163` therefore falls back to inferring `high` from `threat_class == "cryptomining"`. Stage 4 runs must be produced with the field populated so the gate is genuinely variant-aware rather than inferred. Verification: after 4a, assert `expected_cpu_profile` is present in **55/55** new `index.json` files and equals the plan's `CPU Profile` column for that template.

### P3. `manifest_v2.json` design (design only — do not freeze)

Draft exists at `docs/PREREGISTRATION.md:66-71` (working draft, explicitly not frozen). It must be extended before 4b to match the new plan:

- per-run directory isolation `data/raw/runs/<run_id>/<source>/` (already the on-disk layout);
- 55 templates, 400 runs, class mix 140/80/80/60/40;
- `expected_cpu_profile` per run (P2);
- the split must be **grouped by template** (see P4), not by `run_id` as `docs/PREREGISTRATION.md:71` currently states;
- the 5 exfil pilot runs carry `class_status: "pilot only, class dropped"` in `index.json` and must be excluded from every class-level statistic.

**Discrepancy to flag, not silently resolve:** `datasets/splits/manifest_v1.json` is committed and is the manifest of the **invalidated** synthetic dataset (`docs/GATE_REPORTS.md:1285`). It must not be reused or extended. It needs its own deprecation decision at Ticket `07`.

### P4. Split grouped by template (and by run)

- Grouping unit = **template**: every run of a given `TMPL-*` must land entirely on one side of the split, otherwise the same command text and the same Falco rule set appear in both Dev and Test and the Test result is contaminated.
- Proposed sizes from `docs/SCENARIO_PLAN_v2.md` §1: **Dev 289 / Test 111** (72.25 % / 27.75 %).
- `docs/PREREGISTRATION.md:71` still says "288 Dev, 112 Test grouped strictly by `run_id`" and `docs/TICKET_TREE.md:204` still says "frozen test split (112 runs)". Both are stale against the new plan and must be reconciled before any split file is written.
- **The Test split file must not be written during Stage 4.** First access to Test remains Ticket `12c` (row 204; `docs/TICKET_TREE.md:144` Checkpoint I). During 4b, only the *Dev* assignment may be materialised; the Test side is recorded as a name list with no feature/statistic access.
- Cross-check requirement: `scripts/verify_dataset.py` already runs GroupKFold grouped by scenario variant (`:341-348` region) and a metadata-shuffle invariance test (`:204-227`). A grouped-by-template check must be added or confirmed for the final manifest.

### P5. Signature-table tooling — **WRITTEN**

`scripts/signature_table.py` now exists and is read-only (it opens telemetry files for reading only; it never writes, moves or deletes).

```bash
PYTHONPATH=src:. uv run python scripts/signature_table.py --runs-dir data/raw/runs
PYTHONPATH=src:. uv run python scripts/signature_table.py --runs-dir data/raw/runs --json
```

Signature = `(Falco rule set | audit verbs | Hubble flow band | CPU band)`. Hubble bands: LOW 0–6, MID 7–11, HIGH 12+. CPU bands: LOW (peak < 40 m), MID (peak 40–100 m), HIGH (median ≥ 100 m). Runs carrying a `class_status` (the 5 dropped exfiltration runs) are printed in the per-run detail but **excluded** from the per-class statistics.

The script has been run on the 25 real pilot runs. **Three of four classes are FLAGGED at ≥ 60 %** — see §2.5 and the caveat in §2.7. The 4a smoke must recompute this on 55 fresh runs; the pilot result is a warning, not the final table.

### P6. Environment readiness (read-only checks, no cluster mutation)

- Receiver pre-check passes (§4.1).
- `make check-kube-context` confirms context `kind-runtimelens`.
- VM headroom: RAM available ≥ 2048 MB, disk < 80 % — the same thresholds the runner enforces.
- `data/raw_backup/` exists and is git-ignored (`.gitignore:16`); `data/raw/`, `data/scenarios/`, `data/audit/` are ignored (`.gitignore:15,22,17`). No raw telemetry or progress file may be committed.

### P7. Open discrepancy to resolve before 06c launches (flagged, not resolved here)

`docs/TICKET_TREE.md:197` still describes the dataset as "400 live cluster runs (60 esc, 60 prv, 60 cry, 40 unk, 180 ben) across 5 seeds; 3 paired families". The new plan is 80/80/60/40/140 over 55 templates. The ticket text is stale and must be updated — or the plan must be re-justified — **before** Checkpoint F. This runbook does not silently resolve it.

---

## 2. Stage 4a — Smoke: exactly 1 run per template (55 runs), then STOP

### 2.1 Purpose

Validate the full 5-source capture path, the per-run gate, the cooldown behaviour and the real Table F across **all 55 templates at once**, using real telemetry, before spending the full 400-run budget. 4a is a smoke stage, not a pilot: 1 run per template, no repeats.

### 2.2 Run count and manifest

- **Exactly 55 runs** — one per `TMPL-*` row in `docs/SCENARIO_PLAN_v2.md`.
- Run IDs must be derived from the template ID and must not contain class names (the linter's class-leak rule applies to cluster resources; the `index.json` `scenario_id` field is already on the linter's own leakage watch list in `scripts/verify_dataset.py:36-40`, and `verify_dataset.py` scans the telemetry files for `SC-`, `privilege_abuse`, `container_escape`, `cryptomining`).
- The run list is written to `data/scenarios/stage4a_manifest.json` **before** the first run, with one entry per template: `run_id`, `template_id`, `namespace`, `workload`, `expected_cpu_profile`, `expected_falco_rules`, `expected_features_00_01_02`, `expected_audit_verbs`, `expected_hubble_band`, `length_bin`, `command`.

### 2.3 Execution order

1. **Receivers pre-check** (§4.1) — must pass before the first run.
2. **Resource pre-check** — RAM ≥ 2048 MB, disk < 80 %.
3. For each of the 55 runs, in manifest order:
   - cooldown wait (§4.4);
   - execute the template command via `kubectl exec -n <ns> <pod> -- /bin/sh -c <cmd>` (shell delivery is identical for every template, by design, so shell cannot separate classes);
   - periodic cAdvisor sampling every 10 s during execution (as in `scripts/stage2_pilot.py:738-741`);
   - capture all 5 sources into `data/raw/runs/<run_id>/`;
   - write `index.json` **with** `expected_cpu_profile` (P2);
   - per-run gate (§4.3) — a failure aborts 4a immediately;
   - cleanup, then copy the run directory to `data/raw_backup/<run_id>/`.
4. **Dataset gate:** `scripts/verify_dataset.py --runs-dir data/raw/runs`
   (real CLI — the flag is `--runs-dir`, default `data/raw/runs`; there is no `--strict` flag).
5. **Real Table F:** the new §P5 script, run over the 55 collected runs.
6. **STOP for human review.** No batch 2 of 4b begins until the review is recorded.

### 2.4 What 4a must produce

| Artifact | Content |
|:---|:---|
| `docs/reviews/stage4a_summary.md` | 55/55 runs completed, per-class counts, every failure with its raw error |
| `docs/reviews/stage4a_verify_output.txt` | verbatim stdout+stderr of `scripts/verify_dataset.py --runs-dir data/raw/runs` |
| `docs/reviews/stage4a_signature_table.md` | the real Table F (4-field signature per class, largest-share per class, ≥ 60 % flags) |
| `docs/reviews/stage4a_falco_rules_observed.md` | every Falco rule name actually observed, with event counts and the runs in which it fired |

### 2.5 4a success criteria (all must hold)

1. 55/55 runs present, each with all 5 source files.
2. `verify_dataset.py` verdict `GATE VERDICT: PASSED` (zero leakage, zero metadata-shuffle failures, zero sustained-CPU violations) — verbatim output saved.
3. `expected_cpu_profile` present in 55/55 new `index.json` files and matching the plan.
4. Cooldown behaved as specified on every run that needed it (recorded wait durations).
5. Real Table F computed with `scripts/signature_table.py`. **The plan-level Table F in `docs/SCENARIO_PLAN_v2.md` §6.1 is not a gate** — it is a hypothesis, and on the 25-run pilot it was already contradicted (§2.7). The 4a requirement is that the table is computed from real telemetry and reported faithfully, with every class at ≥ 60 % flagged. Whether a flag blocks 4b is a human decision.
6. A named list of Falco rules actually observed (see §2.6).

### 2.6 Specific open item the 4a smoke must settle: `Contact K8S API Server From Container`

`docs/SCENARIO_PLAN_v2.md` lists `Contact K8S API Server` as an *expected* Falco rule for `TMPL-PRV-01`, `-03`, `-05`, `-07`. Verified during this review:

- the rule **is** a stock Falco rule, defined at line 840 of `/etc/falco/falco_rules.yaml` inside the Falco container, shipped by Helm chart **`falco-9.2.0`** (app version `0.45.0`);
- its tags are `[maturity_stable, container, network, k8s, mitre_discovery, T1565]` — **no class names**;
- it is **not** in our `customRules` (`lab/falco/falco-values.yaml` → `runtimelens_rules.yaml`; grep count = 0);
- its condition requires `k8s_api_server` = `(fd.sip.name="kubernetes.default.svc.cluster.local")` and `not user_known_contact_k8s_api_server_activities` (that macro is `never_true`, so it does not block);
- **it has never fired in any real telemetry collected by this project**: 0 occurrences in the Falco container log, and 0 across all 25 collected pilot runs. The three rules that *did* fire in real pilot data are `Interactive Shell Spawned in Non-Debug Container` (26 events / 25 runs), `Suspicious High Port Egress` (16 / 8) and `Read Sensitive Host Information Untrusted` (5 / 5).

**Therefore the plan's expectation is UNVERIFIED in real telemetry and is treated as unverified.** The 4a smoke must record whether the rule fires for the privilege templates; the templates must use the API server **DNS name** (`kubernetes.default.svc.cluster.local`) rather than the raw ClusterIP for the stock condition to be satisfiable. Until 4a shows it in real events, `docs/SCENARIO_PLAN_v2.md` must not rely on it, and `docs/BASELINES.md:123` (which maps it to `privilege_abuse`) is a design-time claim only.

**Action taken 2026-10-20:** `Contact K8S API Server` has been **removed** from the `Expected Falco Rules` column of `TMPL-PRV-01`, `-03`, `-05` and `-07` in `docs/SCENARIO_PLAN_v2.md`, and the plan gained a new §2.1 table grounding the remaining rule names in observed telemetry only.

### 2.7 Real Table F on the 25 pilot runs — three of four classes FLAGGED

`scripts/signature_table.py` was run against the 25 collected pilot runs (read-only). Result:

| Class | Runs | Distinct signatures | Largest single signature | Flagged (≥ 60 %) |
|:---|--:|--:|--:|:--|
| `benign` | 5 | 2 | 80.0 % | **yes** |
| `container_escape` | 5 | 1 | **100.0 %** | **yes** |
| `cryptomining` | 5 | 2 | 80.0 % | **yes** |
| `privilege_abuse` | 5 | 3 | 40.0 % | no |

**This contradicts the plan-level Table F in `docs/SCENARIO_PLAN_v2.md` §6.1, which reported no class at or above 60 %.** The plan-level table was computed from the *plan's expected columns*, not from telemetry. On real telemetry the pilot's 25 runs collapse into very few signatures because the pilot executed only **one scenario per class** (`SC-BEN-01`, `SC-ESC-01`, `SC-PRV-01`, `SC-MNR-01`, `SC-EXF-01`) — every benign run had the same Falco rule set, the same audit verbs, the same Hubble flow count and the same CPU band.

**Reading this correctly:** the 100 % for `container_escape` is **not** evidence that the plan is broken; it is evidence that the pilot had only one escape scenario. The new plan's 55 templates exist precisely to create signature variety inside each class. The 4a smoke is the first measurement that can settle this, because it runs **1 run per template** and therefore samples 21 benign / 10 escape / 8 privilege / 8 mining / 8 unknown distinct template shapes.

**Consequence for the 4a success criteria (§2.5):** criterion 5 is restated as *report the real table faithfully and flag every class at ≥ 60 %*. Whether the flag blocks 4b is a human decision, and it is a decision that must be made on 4a data, not on this 25-run pilot.

---

### 2.8 Stage 4a **Round 2** — the changed and never-run templates only, one run each, then STOP

Round 1 (the Part 1 smoke) executed ten templates. Between Round 1 and Round 2 the plan changed for a set of templates, and a second set had never been executed at all. Round 2 therefore re-runs **only** the templates that were *changed* or *never run*, exactly once each, and then stops for human review. No template that was already executed unchanged is repeated, so no telemetry is collected twice.

| # | Run ID | Template | Class | Why it is in Round 2 | `proc.cmdline` | Bin | Net obs. | CPU profile |
|--:|:---|:---|:---|:---|--:|:---:|:--:|:---|
| 1 | `run-s4a-r2-01` | `TMPL-ESC-05` | `container_escape` | **changed** — replaced (cgroup v2 hierarchy exposure replaces the cgroup v1 `release_agent` traversal) | 228 | 151–250+ | A | `low` |
| 2 | `run-s4a-r2-02` | `TMPL-ESC-08` | `container_escape` | **changed** — replaced (read-only `/dev` enumeration replaces the blocked `mknod` attempt) | 91 | 81–150 | B | `low` |
| 3 | `run-s4a-r2-03` | `TMPL-ESC-09` | `container_escape` | **never run** — needs the four inert dummy files (P1b) | 252 | 151–250+ | C | `low` |
| 4 | `run-s4a-r2-04` | `TMPL-ESC-10` | `container_escape` | **changed** — replaced (containerd dummy socket exposure; `Policy Warning` expectation removed) | 112 | 81–150 | = own probe | `low` |
| 5 | `run-s4a-r2-05` | `TMPL-PRV-02` | `privilege_abuse` | **changed** — re-scoped to the unauthenticated own-namespace enumeration | 88 | 81–150 | = own API request | `low` |
| 6 | `run-s4a-r2-06` | `TMPL-PRV-04` | `privilege_abuse` | **never run** — cross-tenant ConfigMap extraction with the ServiceAccount token | 181 | 151–250+ | = own API request | `low` |
| 7 | `run-s4a-r2-07` | `TMPL-PRV-05` | `privilege_abuse` | **changed** — re-scoped to ServiceAccount-authenticated API group discovery | 148 | 81–150 | = own API request | `low` |
| 8 | `run-s4a-r2-08` | `TMPL-BEN-06` | `benign` | **never run** — ServiceAccount-authenticated own-namespace self-introspection | 175 | 151–250+ | = own API request | `low` |
| 9 | `run-s4a-r2-09` | `TMPL-BEN-14` | `benign` | **never run** — developer debug session with a bounded arithmetic loop | 206 | 151–250+ | B | `burst` |
| 10 | `run-s4a-r2-10` | `TMPL-BEN-16` | `benign` | **never run** — multi-file log compression routine | 252 | 151–250+ | A | `burst` |
| 11 | `run-s4a-r2-11` | `TMPL-BEN-17` | `benign` | **never run** — batch calculation script | 233 | 151–250+ | C | `burst` |
| 12 | `run-s4a-r2-12` | `TMPL-PRV-07` | `privilege_abuse` | **never run** — node proxy reconnaissance loop | 223 | 151–250+ | = own API request | `burst` |
| 13 | `run-s4a-r2-13` | `TMPL-UNK-R2` | `unknown` | **never run** — authorised batch recomputation (recalibrated below the 100 mcores median floor) | 155 | 151–250+ | A | `burst` |

The **Net obs.** column is the Decision D-29 benign network observation: `A` = `nslookup kubernetes.default.svc.cluster.local`, `B` = `nc -z -w 1 10.96.0.10 53`, `C` = `wget -qO- --no-check-certificate https://10.96.0.1/api`, `D` = `echo p | nc -u -w 1 198.51.100.22 8080`. `= own probe` / `= own API request` marks a template whose scenario already produces Hubble flow telemetry and therefore needs no added observation. The full per-template mapping and the per-class A/B/C mix are in `docs/SCENARIO_PLAN_v2.md` §3.6.3.

**Thirteen runs, one per template, then STOP for human review.** No 4b batching starts from this round.

**Execution:** the runner selects the round explicitly. The template set is defined in `scripts/stage4a_runner.py` as `TEMPLATES` (Round 1) and `ROUND2_TEMPLATES` (Round 2), selected by `select_templates(round_id)`.

```bash
# inside the VM, from the synced repository root
cd /home/ubuntu/RuntimeLens
PYTHONPATH=src:. python3 scripts/stage4a_runner.py 2
```

**Round 2 stop rules (identical to Round 1, plus one extra):**

| Stop trigger | Action |
|:---|:---|
| per-run gate FAIL | hard stop, preserve the run directory, report |
| RAM available < 2 GiB | hard stop |
| disk usage > 80 % | hard stop |
| any receiver (4245 / 8765 / 8766) not listening | hard stop |
| leftover pod or namespace after cleanup | hard stop |
| **`burst` peak outside the Decision D-26 band (20–150 mcores) or median >= 100 mcores** | hard stop — the burst calibration of `BEN-14`, `BEN-16`, `BEN-17`, `PRV-07`, `UNK-R2` is **unmeasured**, and the first measurement decides whether the template's CPU profile is correct or must be re-specified |
| any template completes | **STOP for human review — do not proceed to 4b** |

**Round 2 attempt 3 — measured outcome of the nine executed templates.**

| Run | Template | `proc.cmdline` | Bin | Falco | Audit | Hubble | Prom | CPU peak/median (m) | Expected rules fired? |
|:---|:---|--:|:---:|--:|--:|--:|--:|:---|:---|
| `run-s4a-r2-01` | `TMPL-ESC-05` | 228 | 151–250+ | 1 | 5 | 3 | 2 | 0.68 / 0.34 | yes |
| `run-s4a-r2-02` | `TMPL-ESC-08` | 91 | 81–150 | 1 | 5 | 7 | 2 | 0.70 / 0.35 | yes |
| `run-s4a-r2-03` | `TMPL-ESC-09` | 252 | 151–250+ | 3 | 5 | 9 | 2 | 2.33 / 1.17 | **no** — the mount rule shadows the identity rule (REPORT_DELTA §9.1) |
| `run-s4a-r2-04` | `TMPL-ESC-10` | 112 | 81–150 | 1 | 5 | 7 | 2 | 0.51 / 0.26 | **no** — `ls -l` only stats the file, no open event (REPORT_DELTA §9.2) |
| `run-s4a-r2-05` | `TMPL-PRV-02` | 88 | 81–150 | 1 | 6 | 10 | 2 | 0.00 / 0.00 | yes (audit: `list` / `system:anonymous` / 403) |
| `run-s4a-r2-06` | `TMPL-PRV-04` | 187 | 151–250+ | 1 | 6 | 10 | 2 | 0.00 / 0.00 | yes (audit: `list` / `system:serviceaccount:tenant-a:default` / 403) |
| `run-s4a-r2-07` | `TMPL-PRV-05` | 153 | 151–250+ | 1 | 6 | 10 | 2 | 1.12 / 0.56 | yes (audit: `get` / `system:serviceaccount:tenant-b:default` / 200) |
| `run-s4a-r2-08` | `TMPL-BEN-06` | 181 | 151–250+ | 1 | 6 | 10 | 2 | 1.61 / 0.81 | yes (audit: `list` / `system:serviceaccount:tenant-b:default` / 403) |
| `run-s4a-r2-09` | `TMPL-BEN-14` | 206 | 151–250+ | 1 | 5 | 8 | 3 | 0.00 / 0.00 | yes (gate FAILED on the burst band) |

Not executed: `TMPL-BEN-16`, `TMPL-BEN-17`, `TMPL-PRV-07`, `TMPL-UNK-R2`.

### 2.9 Stage 4a **Round 3** — the seven changed or never-run templates, one run each, then STOP

Round 3 follows the approved D-30 / D-31 edit round. It re-runs **only** the templates whose command, pod specification or expected signals changed, plus the four Round 2 templates that were never reached. The six unchanged Round 2 runs (`r2-01`, `r2-02`, `r2-05`, `r2-06`, `r2-07`, `r2-08`) are kept exactly as they are.

| # | Run ID | Template | Why it is in Round 3 | `proc.cmdline` | Bin | Profile | Net obs. |
|--:|:---|:---|:---|--:|:---:|:---:|:--:|
| 1 | `run-s4a-r2-03` | `TMPL-ESC-09` | the Falco rule order changed (D-31) | 252 | 151–250+ | `low` | C |
| 2 | `run-s4a-r2-04` | `TMPL-ESC-10` | the pod is now privileged and the socket is really read (D-31) | 129 | 81–150 | `low` | B |
| 3 | `run-s4a-r2-09` | `TMPL-BEN-14` | burst re-calibrated (D-30) | 218 | 151–250+ | `burst` | B |
| 4 | `run-s4a-r2-10` | `TMPL-BEN-16` | burst re-calibrated (D-30) | 211 | 151–250+ | `burst` | C |
| 5 | `run-s4a-r2-11` | `TMPL-BEN-17` | burst re-calibrated (D-30) | 174 | 151–250+ | `burst` | A |
| 6 | `run-s4a-r2-12` | `TMPL-PRV-07` | CPU profile re-declared `low` (D-30) | 229 | 151–250+ | `low` | = own API request |
| 7 | `run-s4a-r2-13` | `TMPL-UNK-R2` | burst re-calibrated (D-30) | 155 | 151–250+ | `burst` | A |

```bash
# inside the VM, from the synced repository root
cd /home/ubuntu/RuntimeLens
PYTHONPATH=src:. python3 scripts/stage4a_runner.py 3
```

**Round 3 stop rules** — identical to Round 2, including the burst-band rule, and the round ends with a **STOP for human review** after the seventh run. The D-26 band and the D-27 post-lag rule are unchanged.

**Round 2 evidence to paste (identical format to Round 1):** per-run table; `scripts/verify_dataset.py --runs-dir <round2 dir>` output; `scripts/signature_table.py --runs-dir <round2 dir>` output; the fired-vs-expected Falco rule comparison for all thirteen runs; features 00/01/02 for the four escape runs with their `pod/spec.json` files; `kubectl get pods -A`; `kubectl get ns`; `free -h`; `df -h /`; and the `ls -la` output of the dummy directories (P1b verification).

### 2.10 Stage 4a **Round 4** — ESC-04 and ESC-09 only, one run each, then STOP

Round 4 re-runs the two templates whose command changed under Decision D-31 (a read of a **non-identity** dummy file was added so that the mount rule has an event of its own, since Falco yields one rule per event). The `TMPL-ESC-04` telemetry collected in Part 1 is stale with respect to the deployed rule order and must be re-collected.

| # | Run ID | Template | Why | `proc.cmdline` | Bin | Expected rules |
|--:|:---|:---|:---|--:|:---:|:---|
| 1 | `run-s4a-05` | `TMPL-ESC-04` | the dummy `shadow` read is owned by the identity rule; a `hosts` read gives the mount rule its own event | 161 | 151–250+ | Shell Spawn, Sensitive Mount, Sensitive File Read |
| 2 | `run-s4a-r2-03` | `TMPL-ESC-09` | same addition | 309 | 151–250+ | Shell Spawn, Sensitive Mount, Sensitive File Read |

```bash
cd /home/ubuntu/RuntimeLens
PYTHONPATH=src:. python3 scripts/stage4a_runner.py 4
```

### 2.11 Round 4 — **PROPOSAL ONLY, NOT EXECUTED**

32 of the 55 registered templates have never been executed. The proposal below batches them in groups of ten, **grouped by class inside each batch** (the templates of a class are contiguous) and arranged so that **every class is represented in every batch that contains it**, so that a mid-batch stop still leaves the collected set spanning all five classes. The last batch holds the two remaining templates because 32 is not a multiple of ten.

**Prerequisite: the commands of these 32 templates do not exist yet.** Writing them is a separate, reviewable step that must respect everything the Stage 4a rounds established:
* the twelve **local-only** templates (`BEN-02`, `BEN-03`, `BEN-08`, `BEN-10`, `BEN-15`, `ESC-01`, `ESC-02`, `ESC-07`, `UNK-04`, `UNK-07`, `UNK-R1`, `UNK-R4`) must carry exactly **one declared D-29 network observation** (type A, B or C), otherwise they produce zero Hubble flows and fail the per-run gate;
* the BusyBox `wget` option form is **`--header=`** (never `-H`);
* the three unthrottled mining templates (`MNR-01`, `MNR-02`, `MNR-05`, `high` profile, 130 s) must reproduce the Decision D-22 busy-loop calibration, and the four throttled ones (`MNR-04`, `MNR-06`, `MNR-07`, `MNR-08`) the Decision D-27 post-lag profile;
* every command's length must be measured and the registry's length bin corrected to the measured value before the run.

| Batch | Templates (class-grouped) | Classes | Est. wall time |
|:--:|:---|:---|--:|
| **1** | `MNR-01`, `MNR-02`, `MNR-04`, `MNR-05`, `MNR-06`, `MNR-07`, `MNR-08` (mining) → `PRV-06`, `PRV-08` (privilege) → `ESC-01` (escape) | mining, privilege, escape | ~25 min (the three 130 s mining templates dominate) |
| **2** | `UNK-04`, `UNK-05`, `UNK-07`, `UNK-R1`, `UNK-R3`, `UNK-R4` (unknown) → `ESC-02`, `ESC-07` (escape) → `BEN-02`, `BEN-03` (benign) | unknown, escape, benign | ~8 min |
| **3** | `BEN-05`, `BEN-07`, `BEN-08`, `BEN-09`, `BEN-10`, `BEN-12`, `BEN-13`, `BEN-15`, `BEN-18`, `BEN-19` (benign) | benign | ~6 min |
| **4** | `BEN-20`, `BEN-21` (benign) | benign | ~2 min |

Class coverage check: benign 2+10+2 = 14, escape 1+2 = 3, privilege 2, mining 7, unknown 6 — **32 templates, all five classes covered**.

**Not executed.** Round 4 requires (a) the 32 command texts to be written and their length bins re-derived, (b) an approval of the batch plan, and (c) a runner round selection for each batch.

**Round 3 attempt history.**

| Attempt | Scope | Result | Status |
|:--:|:---|:---|:---|
| 3 | 7 templates: `ESC-09`, `ESC-10`, `BEN-14`, `BEN-16`, `BEN-17`, `PRV-07`, `UNK-R2` | 7/7 executed, no gate failure | Two deviations remain, both reported in `docs/REPORT_DELTA.md` §11.1 (the mount rule cannot fire in `ESC-09` because the identity rule now owns the only files it reads) and §11.2 (`PRV-07` produced 46 Hubble flows, i.e. the HIGH band, not the planned MID). Both need a further approved template edit and a Round 4. The `TMPL-ESC-04` Part 1 telemetry is also stale with respect to the Decision D-31 rule order and must be re-run. |

**Round 2 attempt history.**

| Attempt | Stopped at | Stop reason | Status |
|:--:|:---|:---|:---|
| 1 | run 1 (`TMPL-ESC-05`) | `Missing telemetry from source 'hubble': count=0` — the scenario was purely local | Resolved by Decision D-29 (one declared benign network observation per local-only scenario; the **gate was not changed**) |
| 2 | run 6 (`TMPL-PRV-04`) | `Missing telemetry from source 'hubble': count=0` — the command used the `-H` header option that **BusyBox `wget` does not support**, so it aborted before any network request | Resolved by restoring the verified `--header=` form in `TMPL-PRV-04`, `TMPL-PRV-05`, `TMPL-BEN-06` and `TMPL-PRV-07`; regression tests pin the option form |
| 3 | run 9 (`TMPL-BEN-14`) | `burst band: FAIL (peak=0.00m not in [20,150])` — the kubelet's cAdvisor collection cadence is ~18–20 s, so a 6-second CPU burst is invisible to the summary API | **Open.** The scenario calibration, not the gate, must change: see `docs/REPORT_DELTA.md` §9.3. The gate and the D-26/D-27 thresholds are unchanged |

Every failed attempt is retained for audit. `data/raw_backup/run-s4a-r2-01` and `data/raw_backup/run-s4a-r2-06` are the authoritative copies; the working copies were moved to `data/raw/failed_runs/` so that they are neither reused as dataset runs nor overwritten by a re-run, and the superseded (gate-passing but pre-fix) copies of runs 01–05 were moved to `data/raw/superseded_runs/`. Nothing was deleted.

**Round 2 decisions that must be settled before 4b may start:**

1. Did `Launch Sensitive Mount Container` fire on `TMPL-ESC-09` and `TMPL-ESC-10`?
2. Did `Read Sensitive Host Information Untrusted` fire on the dummy `shadow` read in `TMPL-ESC-09`?
3. Did the four escape runs report the planned feature triples (F/F/T, F/F/T, F/T/F, T/F/T)?
4. Did `TMPL-PRV-02` (unauthenticated) and `TMPL-PRV-05` (API group discovery) both produce a **captured** audit record with the expected verbs?
5. Do the five `burst` templates land inside the Decision D-26 band with a Decision D-27-compliant post-lag median?
6. Does the Round 2 signature table flag any class as having >= 60 % of its runs in a single signature?

---

## 3. Stage 4b — Full 400 runs in resumable batches of 20

### 3.1 Batch structure

- Batch size = **20 runs**; 400 runs = **20 batches**.
- Batches are ordered so that each batch is internally homogeneous enough to be diagnosable but proportional to the class mix: a proportional batch is ≈ 7 benign / 4 escape / 4 privilege / 3 mining / 2 unknown.
- Mining templates are spread across batches, never clustered, so a single miner-induced resource event cannot take out a whole batch.
- **Resumability:** on restart the runner skips any `run_id` already present in `data/raw/runs/` and in the progress file. A completed run is never re-executed and never overwritten.

### 3.2 Progress file

`data/scenarios/stage4_progress.json` (git-ignored via `.gitignore:22`), written after every run and after every batch:

```json
{
  "stage": "4b",
  "batch_size": 20,
  "batches_total": 20,
  "batches_completed": 0,
  "runs_completed": 0,
  "runs_total": 400,
  "current_batch": 1,
  "last_completed_run_id": null,
  "last_completed_template_id": null,
  "started_at": "<UTC ISO8601>",
  "updated_at": "<UTC ISO8601>",
  "cooldown_events": {"count": 0, "max_wait_seconds": 0.0, "timeouts": 0},
  "stop_reason": null,
  "receivers_checked_at": "<UTC ISO8601>",
  "resource_snapshot": {"ram_avail_mb": null, "disk_use_pct": null}
}
```

The existing `data/scenarios/run_checkpoint.json` is the artifact of the **invalidated** 06c run and must not be reused as-is.

### 3.3 Per-batch checklist (identical for all 20 batches)

1. Receivers pre-check (§4.1) — record pass/fail and timestamp.
2. Resource check — RAM and disk (§4.4).
3. Execute the 20 runs (§2.3 steps 3.1-3.7).
4. Per-run gate on all 20 runs — any failure aborts the batch.
5. `scripts/verify_dataset.py --runs-dir data/raw/runs` over the whole dataset to date.
6. Backup of the batch (§3.5).
7. Update the progress file; write `docs/reviews/stage4b_batch_NN_report.md`.
8. Resource snapshot after the batch.

### 3.4 Stop rules — hard, immediate

Stage 4b halts at once, writes `stop_reason` into the progress file, saves the batch report, and does **not** start the next batch, on any of:

1. **RAM available < 2 GiB** (2048 MB) — checked before the run, every second during the run, and after the batch. `scripts/stage2_pilot.py:711-713` (pre-run) and `:749-753` (in-run, which terminates the exec, cleans the pod, and raises).
2. **Disk utilisation ≥ 80 %** — same three checkpoints, same code path.
3. **Receiver down** — Hubble 4245, Falco webhook 8765 or Audit webhook 8765→8766 unreachable. `scripts/stage2_pilot.py:57-61` raises `RuntimeError("PRE-RUN CHECK FAILED: …")`.
4. **Gate failure** — per-run gate (`scripts/stage2_pilot.py:474-632`) or dataset gate (`scripts/verify_dataset.py`) fails for any run; or the cooldown cannot be satisfied within policy after the permitted retry.
5. **Cooldown timeout** — container CPU does not fall below 20 mcores for 2 consecutive samples within 60 s. The existing code only *warns* (`scripts/stage2_pilot.py:720-722`); Stage 4 requires this to be a **batch-level warning recorded in the report and a pause for the operator**, not a silent continuation.
6. **Evidence integrity** — a credential-like string, a private key or a token appears in any log, fixture, diff or index file. Immediate stop, quarantine the artefact, and open an approval-queue entry.
7. **Metadata leakage** — a class name, `SC-*` scenario id or `run-*` id is found inside any telemetry event, feature representation or fact dictionary.
8. **Flakiness / non-determinism** — the same template run twice produces materially different gate-relevant signals, or a lab health check fails twice consecutively.
9. **Human stop** — the operator says stop, for any reason.

### 3.5 Backup after each batch

After batch NN passes its gate, copy the 20 run directories to a batch-scoped location before the next batch starts:

```
data/raw_backup/batch_NN/<run_id>/…
```

`data/raw_backup/` is git-ignored (`.gitignore:16`). Backups are never committed. A per-run backup already happens inside `scripts/stage2_pilot.py:801-804`; the batch-level copy is an additional, batch-scoped copy for recovery of a whole batch, and its presence on disk is asserted in the batch report.

### 3.6 Batch report template — `docs/reviews/stage4b_batch_NN_report.md`

Batch id · run ids and template ids · receivers pre-check result (verbatim) · per-run gate verdicts · cooldown event count / max wait / timeouts · RAM and disk before and after · `verify_dataset.py` output (trimmed, with the exact command) · deviations, stop triggers, and anything skipped · backup path · cumulative progress counters.

---

## 4. Standing rules for every run in 4a and 4b

### 4.1 Receivers pre-check

Run before the first run of 4a and before **every** batch of 4b. All three must be listening, on loopback / the documented bridge address only — no `NodePort`, no `hostPort`:

| Receiver | Port | Addresses checked | Source |
|:---|--:|:---|:---|
| Hubble relay port-forward | 4245 | `127.0.0.1`, `localhost` | `scripts/stage2_pilot.py:58` |
| Falco webhook receiver | 8765 | `172.18.0.1`, `127.0.0.1` | `scripts/stage2_pilot.py:59` |
| Audit webhook receiver | 8766 | `172.18.0.1`, `127.0.0.1` | `scripts/stage2_pilot.py:60` |

Implementation: `verify_receiver_ports_listening()` (`scripts/stage2_pilot.py:57-61`). Any failure → stop rule 3.

### 4.2 Per-run capture requirement

Every run directory must contain all 5 sources: `falco/events.jsonl`, `audit/events.jsonl`, `hubble/flows.jsonl`, `prometheus/metrics.json`, `trivy/report.json`. This layout is already produced by the real pilot (`ls data/raw/runs/run-test-01-prv/`) and is the on-disk contract `scripts/verify_dataset.py:56-201` audits.

### 4.3 Per-run gate (variant-aware)

`verify_per_run_gate(run_dir, expected_cpu_profile)` (`scripts/stage2_pilot.py:474-632`) plus the dataset-level variant-aware CPU gate in `scripts/verify_dataset.py:270-299`:

| `expected_cpu_profile` | Duration | Prometheus samples | CPU condition |
|:---|--:|--:|:---|
| `high` | ≥ 115 s | ≥ 8 | ≥ 80 % of samples ≥ 100 mcores |
| `throttled` | ≥ 50 s | ≥ 5 | ≥ 60 % of samples ≥ 40 mcores |
| `burst` | — | ≥ 1 | **peak in [30, 100] mcores AND median < 100 mcores** |
| `low` | — | — | no sustained-CPU requirement |

**Closed 2026-10-20:** the `burst` profile previously enforced **nothing** — it printed `PASS (Burst profile)` unconditionally, so a burst template that never spiked CPU passed silently. `scripts/verify_dataset.py` now enforces the band above (peak between 30 and 100 mcores, median strictly below 100), counts violations in a new `burst_violations` counter, and reports them in the gate verdict. Covered by 7 unit tests in `tests/unit/test_verify_dataset_cpu_band.py`.

The `burst` band deliberately **excludes** sustained load: a median at or above 100 mcores is the `high` profile's signature, and a peak above 100 mcores is a mining-shaped spike, not a burst.

### 4.4 Cooldown rule (variant-aware)

`wait_for_pod_cooldown(namespace, pod_name, max_wait_seconds=60.0)` (`scripts/stage2_pilot.py:659-677`):

- poll container CPU from the cAdvisor summary API (`get_container_current_cpu_mcores`, `:633-656`);
- require CPU **< 20 mcores for 2 consecutive samples**;
- sample interval 3 s, **hard cap 60 s**;
- on timeout the current code only logs a warning (`:720-722`).

Stage 4 requirement: the cooldown applies **before every run**, and is **stricter for CPU-intensive profiles** — `high` and `throttled` templates must reach cooldown, `burst` templates should, and `low` templates may skip it. Timeout behaviour is **rotate → warn → abort**: rotate the offending run to the end of the next batch, record a warning in the batch report, and abort the batch if a second timeout occurs on the same template within the same batch. Abort of the batch is a stop-rule-5 trigger.

### 4.5 Telemetry manipulation prohibition

No pausing of Falco, no truncation or editing of audit records, no timestamp skew, no mutation of any cluster component, and no injected synthetic events. Every `unknown` template is real live behaviour (the 4 harness-manipulating templates — `UNK-01`, `-02`, `-06`, `-08` — were withdrawn for exactly this reason). A violation is stop-rule 7.

### 4.6 Safety boundary

Escape templates run only in `sandbox-workloads`; `hostPath` and `privileged` are illegal in tenant namespaces by linter and by Pod Security Standards. No real runtime socket is ever mounted. The API server is contacted only with the pod's own service-account token, and every cross-tenant request is expected to be answered `403 Forbidden` — a `200` on a cross-tenant read is a **lab misconfiguration** and must stop the batch.

---

## 5. Time estimates — all marked **estimate**

> **All figures in §5 are ESTIMATES.** They are derived from the real pilot measurements in §0 and the plan's declared per-template durations. They are planning aids, not commitments, and they are not gate evidence. The first batch of 4b must measure its own wall clock and the estimate must be revised from that measurement.

### 5.1 Basis — the numbers used

**Measured, from `data/raw/runs/*/index.json` → `duration_seconds` (25 real pilot runs):**

| Class | n | mean | min | max |
|:---|--:|--:|--:|--:|
| benign | 5 | 11.57 s | 7.13 s | 25.32 s |
| container_escape | 5 | 7.13 s | 7.12 s | 7.15 s |
| privilege_abuse | 5 | 7.93 s | 7.11 s | 9.15 s |
| cryptomining | 5 | 129.02 s | 124.23 s | 130.29 s |
| exfiltration (dropped) | 5 | 9.14 s | 9.13 s | 9.14 s |

**Plan-declared durations** (`docs/SCENARIO_PLAN_v2.md` → `Duration` column) weighted by planned runs:

| Class | runs | plan scenario time |
|:---|--:|--:|
| benign | 140 | 1547 s (25.8 min) |
| container_escape | 80 | 720 s (12.0 min) |
| privilege_abuse | 80 | 820 s (13.7 min) |
| cryptomining | 60 | 5790 s (96.5 min) |
| unknown | 40 | 955 s (15.9 min) |
| **Total** | **400** | **9832 s = 163.9 min = 2.73 h** |

### 5.2 Estimates

| Quantity | Estimate | Derivation |
|:---|--:|:---|
| **Stage 4a total wall clock (55 runs)** | **≈ 23 min of scenario time**, plus capture/cleanup overhead already included in the pilot per-run figures | plan duration summed once per template = 1362 s = 22.7 min |
| **Stage 4a per-run** | 7 s – 130 s | plan durations; mining templates dominate (770 s of the 1362 s) |
| **Stage 4b per batch of 20 (proportional mix)** | **≈ 8.2 min of scenario time** (492 s) | 7 ben × 11.1 s + 4 esc × 9.0 s + 4 prv × 10.2 s + 3 mnr × 96.5 s + 2 unk × 23.9 s |
| **Stage 4b worst-case batch** (3 mining + 17 fast) | **≈ 9.3 min** (560 s) | 17 × 10 s + 3 × 130 s |
| **Stage 4b total, all 20 batches** | **≈ 2.73 h of scenario time** (9832 s) | plan durations × planned runs |
| **Cooldown overhead** | up to +60 s per run that times out, +3 s per sample otherwise | `scripts/stage2_pilot.py:659-677` |
| **Total 4a + 4b** | **≈ 3.1 h of scenario time** | 1362 s + 9832 s |

**Caveats on these estimates (honest):**

- The pilot's per-run figure already includes capture and cleanup, because for 9 of 10 pilot runs `index.json duration_seconds` equals the harness `elapsed_seconds` exactly. The one mismatch (`run-p06-mnr`, 130.13 vs 124.24) is unexplained and is itself a small data-quality item for 4a to re-check.
- The **throttled mining templates have no pilot timing** — the pilot mined at `high` only. `MNR-03`, `-04`, `-06`, `-07`, `-08` are declared at 70–90 s in the plan and are unmeasured; their true wall clock may be longer because the throttle must hold a target rate.
- The **unknown templates have no pilot timing** either; the 9.13 s figure used above is borrowed from the exfiltration pilot, which had a comparable shape but is not the same workload.
- The per-class means above are computed from **n = 5** per class. They are estimates, and 4a is the first opportunity to replace them with n = 1 per template across 55 templates.
- These estimates cover **scenario time only**. They exclude batch-level receivers pre-check, dataset-gate execution over the whole dataset, and the operator review pauses.

---

## 6. References

| Document | Relevance |
|:---|:---|
| `docs/SCENARIO_PLAN_v2.md` | 55 templates, 400-run budget, tables A–F (§6.1 expected, §6.2 real), linter edit in §4 |
| `docs/PREREGISTRATION.md:60-76` | unfrozen `manifest_v2` / `manifest_v2_split` draft |
| `docs/TICKET_TREE.md:193-204` | ticket statuses and dependencies for 06a–08, 09a, 09b, 12a–12c |
| `docs/DECISIONS.md` | D-20 (invalidation), D-24 (exfil dropped), D-25 (model identity) |
| `docs/BASELINES.md:123` | design-time mapping of `Contact K8S API Server From Container` to `privilege_abuse` — unverified in real telemetry |
| `docs/GATE_REPORTS.md:1285` | why `manifest_v1.json` must not be reused |
| `scripts/verify_dataset.py` | dataset gate, variant-aware CPU gate, leakage + shuffle + GroupKFold diagnostics |
| `scripts/stage2_pilot.py` | runner, per-run gate, cooldown, receiver pre-check, resource stop rules, backup |
| `scripts/scenario_safety_lint.py` | safety linter; the single required edit is in §P1 |
| `scripts/analyze_pilot_signals.py` | existing per-class Falco-rule / audit-verb analysis (2 of 4 signature dimensions) |
| `scripts/signature_table.py` | read-only Table F over real run directories (all 4 signature dimensions) |
| `src/runtimelens/collector/per_run_capture.py` | writes `index.json` including `expected_cpu_profile` |
| `data/raw/runs/*/index.json` | the 25 real pilot runs — the timing basis in §0 and §5.1 |
| `data/scenarios/pilot_25_metrics.json` | harness wall clock for 10 real pilot runs (gate PASSED) |

*AI Assistance Disclosure:* this runbook was authored by an AI assistant under direct human direction, using only offline repository inspection plus read-only cluster inspection. No scenario was executed, no telemetry was fabricated, and no gate is claimed as passed.
