# Research artifacts

This directory holds the live-evaluation harness, the measured results and the
figure pipeline that back the project presentation and the IEEE-style paper.

It is an addition to, not a replacement for, the offline-fixture evaluation
recorded in `docs/GATE_REPORTS.md`. Nothing in here is simulated: every number
under `results/` was produced by a real network call at run time.

## Layout

| Path | What it is |
|---|---|
| `live_typed_decision_eval.py` | Harness. Paired baseline-context A/B against live hosted models, plus the four-tier prompt-injection experiment. |
| `analyse_live_results.py` | Post-hoc statistics: mid-p McNemar, group-level paired bootstrap, per-class tests with Holm correction, precision@K, FPR at fixed TPR, confusion matrices. |
| `figures/make_figures.py` | Renders every chart from measured artefacts into `figures/*.png`. |
| `deck/build_deck.js` | Builds `docs/presentation/RuntimeLens_presentation.pptx`. |
| `results/` | Raw per-call rows and the derived analysis. |
| `figures/` | Generated PNG charts. |

## Running it

```bash
export GROQ_API_KEY=...          # required for the Groq arms and the prompt guard
export OPENROUTER_API_KEY=...    # required for the OpenRouter arms
export SCALEDOWN_API_KEY=...     # optional; used for a direct hosted-API probe

# 1. Live paired A/B (baseline context ON vs OFF, per incident)
uv run python -m research.live_typed_decision_eval \
    --arms groq-120b groq-20b or-qwen27b or-deepseek --skip-adversarial --out ab

# 2. Prompt-injection ASR across the four defence tiers
uv run python -m research.live_typed_decision_eval --arms groq-120b or-qwen27b \
    --adversarial-only --out adv

# 3. Statistics
uv run python -m research.analyse_live_results

# 4. Figures
uv run python research/figures/make_figures.py

# 5. Deck
node research/deck/build_deck.js
```

## Protocol notes

- The typed-decision contract is the one in `src/runtimelens/models/rubrics.py`:
  one `choice`, one ordered `score`, four independent `noul` flags, all answered
  against one shared state.
- The `without_baseline` condition removes **only** the `<baseline>` block from
  the state string. Every other field is byte-identical between the two
  conditions, so the paired difference isolates baseline context.
- The state string is produced by the same renderer as the production adapter
  (`serialize_canonical_state` in `src/runtimelens/classifiers/scaledown.py`),
  including XML escaping of untrusted fields.
- API keys are read from the environment only. They are never written to disk,
  never logged, and never embedded in a fixture. `scripts/check_secrets.py`
  enforces this in CI.
- Rate limits: the hosted providers enforce per-minute token budgets. The
  harness throttles per arm and backs off on HTTP 429.

## Honest scope of the live experiment

The incident suite is 28 states derived from the project's own scenario
catalogue (`docs/SCENARIOS.md`), not captured production traffic. The live
experiment is therefore a **controlled replication** of the pre-registered
hypothesis across model families. It is not a field trial, and it does not
establish the effect magnitude in production.
