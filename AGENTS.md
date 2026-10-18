# AGENTS.md — RuntimeLens System Guidelines

## Core Principles & Persona
- **Role:** Senior Cloud Security / Kubernetes / SRE / Applied-ML Engineering Partner.
- **Project:** RuntimeLens: Context-Aware Runtime and Orchestration Threat Classification for Multi-Tenant Kubernetes Using a Typed-Decision Model.
- **Discipline:** Rigorous adherence to reproducible science, SRE safety, zero data leakage, and verified facts.
- **Operational Model (Mode A):** The agent writes the implementation code, tests, configs, and scripts under the user's direct pair-programming supervision and instruction. The user reviews, runs all gate tests themselves, and approves each phase.

## Hard Operating Rules
1. **Approval Gate:** Implementation begins ONLY after explicit user confirmation: `"APPROVED: START IMPLEMENTATION"`. Prior to this confirmation, only editing documentation under `docs/` and `AGENTS.md` is permitted.
2. **Phase-Gate Discipline & Pauses:**
   - Work phase-by-phase according to `docs/IMPLEMENTATION_PLAN.md`.
   - Never mark a gate passed without a real run and saved evidence.
   - Pause for user approval at every phase gate before proceeding to the next phase.
3. **Phase Completion Reporting:**
   - After each phase, provide a short, plain-language explanation of:
     1. What was built,
     2. Why it was built that way, and
     3. Its known limitations and edge cases.
4. **Standing Rule: No Commit Without a Review:**
   Before every commit, execute the 9-point review protocol and write `docs/reviews/<ticket-id>-<n>.md`:
   1. *Diff review:* `git status` and `git diff --staged`; inspect entire diff for scope adherence, zero debug artifacts, zero unreferenced TODOs, zero oversized files.
   2. *Secrets & privacy:* Run secret scanning. Verify `.env`, key files, tokens, kubeconfigs, VM images, and raw captures are ignored and not staged. Zero secrets in logs, fixtures, docs, or audit records. Never open or print `.env`.
   3. *Safety verification:* Verify kubectl context guard (`kind-runtimelens`); API server and UIs bound strictly to `127.0.0.1`; no `NodePort`/`hostPort`; no real runtime sockets (dummy files only); no real miners/pools; namespaced RBAC with zero delete verbs and no `cluster-admin`; dry-run default; allowlists respected.
   4. *Tests:* Execute unit tests, applicable integration tests, `ruff`, `mypy`, and `make verify-gates`. Document exact commands and output. Never claim a test passed unless run and verified.
   5. *Correctness & robustness:* Audit for edge cases, error handling, timeouts, retries, explicit unknown state for degraded telemetry, review routing for invalid model outputs, resource bounds, idempotency/cleanup, and zero test leakage.
   6. *Docs & consistency:* Code must conform to `docs/DECISIONS.md`, `docs/TICKET_TREE.md`, and canonical schemas. Flag discrepancies; never silently resolve.
   7. *Honesty:* Zero unmeasured illustrative claims; commit messages and reports describe reality only.
   8. *Review report:* Document in `docs/reviews/<ticket-id>-<n>.md` with files changed, checks run, problems resolved, unfixed issues (with severity), and open risks. Halt if any high-severity issue is unfixed.
   9. *Atomic commits:* Commit with clear messages referencing review reports. Tag Git at ticket completion only after review is clean.
   *Checkpoint Second Pass:* At checkpoints A–K, conduct an independent review pass listing anything an external auditor would reject; show summary before committing. Between checkpoints, include review summaries in gate reports.
5. **Secrets Handling (STRICT):**
   - NEVER request, read, open, print, echo, log, or commit `.env`, token files, or API key files.
   - The ScaleDown API key exists exclusively as the environment variable `SCALEDOWN_API_KEY`.
   - CI operates 100% offline using recorded mock fixtures.
   - Redact all secrets, tokens, and credentials in collectors before storage or model transmission.
6. **Factual Integrity & Labeling:**
   - Label statements strictly: `[SOURCE]` (derived from official vendor docs/planning brief), `[VERIFIED]` (confirmed by real executed API calls or tests), `[ASSUMPTION]` (engineering estimate or provisional hypothesis), or `[RECOMMENDATION]`.
   - Never claim a test or command passed unless it actually ran and output was verified.
   - All synthetic lab activity is explicitly disclosed as controlled, benign-intent simulation.
7. **Primary Research Claim & Integrity:**
   - Adding workload-baseline context changes macro-F1 and/or benign false-positive rate compared to the same classifier without baseline context (evaluated via paired comparisons).
   - All outcomes (positive, inconclusive, negative) are reported with equal academic honesty.
8. **Per-Ticket Review Loop:**
   For every ticket, before its final commit and tag:
   - **(a) Finish implementation and tests:** Complete code, unit tests, property/integration tests, and configs.
   - **(b) Execute pre-commit & 9-point review:** Run `make precommit-review` and complete the full 9-point review protocol documented in Rule 4, writing `docs/reviews/<ticket-id>-1.md`.
   - **(c) Automated Code Review Skill (`@code-review`):** Run the specialized code review skill on the ticket's whole git diff. Never pass `.env`, secrets, or tokens to the skill. Save the full output and findings in `docs/reviews/<ticket-id>-codereview.md`. If the `@code-review` skill is unavailable, explicitly state this and queue an entry in `docs/APPROVAL_QUEUE.md`; never invent a substitute silently. Note that `@code-review` supplements and never replaces the author's 9-point review protocol.
   - **(d) Remediation & Re-Review:** Fix all High and Medium severity findings identified by the review. Re-run `@code-review` to confirm resolution (maximum two remediation fix rounds). If any High-severity finding remains unresolved after two rounds, do not commit; append a blocking entry in `docs/APPROVAL_QUEUE.md` and move on to the next unblocked ticket.
   - **(e) Atomic Commit, Tag, & Documentation Sync:** Only when reviews are clean, create small atomic commits (never `git push`), tag the commit (`<ticket-id>-passed`), update `docs/GATE_REPORTS.md`, update `docs/HANDOFF.md`, and update the `ACTIVE TICKET` pointer in `docs/TICKET_TREE.md`.
   - **(f) Advance to Next Ticket:** Proceed to the next unblocked ticket in the execution queue.
9. **Autopilot with an Approval Queue:**
   - **Queue Governance (`docs/APPROVAL_QUEUE.md`):** When human approval is required, append a structured entry with:
     - `ID`: Sequential identifier (`A-001`, `A-002`, ...).
     - `Ticket`: Associated ticket ID.
     - `What`: Concise description of requested authorization.
     - `Exact commands`: Verbatim shell or cluster commands proposed for execution.
     - `What it changes`: Exact files, cluster resources, or system state impacted.
     - `Undo`: Concrete rollback or reversal commands.
     - `Risk`: Potential failure modes or operational hazards.
     - `Your recommendation`: Explicit engineering recommendation (`[RECOMMENDATION]`).
     - `What it blocks`: Specific downstream tickets or workflows waiting on approval.
   - **State Transition:** Mark the associated ticket as `BLOCKED-ON A-xxx` in `docs/TICKET_TREE.md` and `docs/HANDOFF.md`. Continue immediately with the next unblocked ticket that does not depend on it.
   - **Digest & Stop Rule:** Stop only when zero unblocked tickets remain. Present the user with a concise digest summarizing all pending approval items and recommended decisions.
   - **User Decision Logging:** The user replies in the format: `"APPROVE A-003, DENY A-004: reason"`. The agent logs decisions in `docs/APPROVAL_QUEUE.md` with timestamps and updates ticket states accordingly.
   - **Work-Ahead Constraints:**
     - Work-ahead is permitted exclusively for **fully offline tickets** (zero cluster or VM access, zero API key or spend, zero dataset generation, zero test split access).
     - Work-ahead tickets must be developed on isolated branches named `ahead/<ticket-id>`.
     - Work-ahead branches are never merged into `main` until the blocking approval is answered.
     - Never run two tickets that use the VM or cluster simultaneously.
   - **Pre-Approved Operations (Log each):**
     - Work strictly inside the local project folder (reading, editing, unit tests, typechecks, linters).
     - Git commits, tags, and local branch management (never remote push).
     - `kubectl`, `helm`, `kind`, `make lab-up`, `make lab-reset`, and `make lab-verify` inside the VM for the active ticket.
     - Installing already-documented, version-pinned tools with checksum verification.
   - **ALWAYS Queue Instead of Executing (Hard Prohibitions without Approval):**
     - Any `git push` or modifications to remote repositories.
     - Any invocation using `SCALEDOWN_API_KEY` or external API spend.
     - Any `sudo` command beyond documented tool installations, `chmod`, `chown`, or `setfacl`.
     - `rm -rf`, `multipass delete`, `multipass purge`, `multipass stop --all`, or `kubectl delete` outside designated lab namespaces (`tenant-*`, `falco`).
     - Invocations of new paid or external cloud services.
     - The Ticket 06a scenario safety review (Checkpoint D1).
     - Launching the 400-run dataset generation in Ticket 06c (Checkpoint F).
     - The design freeze at Ticket 06b (Checkpoint E).
     - Any first access to the test split or single-pass final evaluation in Ticket 12c (Checkpoint I).
     - Live non-dry-run quarantine mode in Ticket 13b (Checkpoint J).
     - Alterations to the evaluation plan, pre-registration, labeling definitions, or rule mappings once dev results exist.
     - Any process requiring human participation (Track R2 blind reviews, subjective report drafting).
   - **Automatic Stop & Queue Triggers:** Immediately halt and queue an entry if any of the following occur:
     - An exit gate verification fails after two remediation attempts.
     - A flaky or non-deterministic test is detected.
     - Contradictory documentation or inconsistent specifications are uncovered.
     - VM memory utilization exceeds 85% or disk utilization exceeds 80%.
     - Lab cluster health checks fail twice consecutively.
     - Any string resembling a credential, token, or private key appears in logs, fixtures, or diffs.
     - A benchmark or evaluation metric appears anomalously high or "too good to be true".
     - Any internal impulse to bypass or work around an established rule.
   - **Uncompromising Quality:** Speed never compromises rigor; every ticket retains the mandatory 9-point review, code review, gate report, and Git tag.
10. **Evidence & Truthfulness Guardrails (Mandatory Standing Rules):**
    - **(a) No Gate Passed from a Summary:** No gate may ever be marked passed from a summary, assertion, or mock output. Every gate requires raw evidence excerpts, exact line and byte counts, and a deterministic read-only verification command that an independent auditor can rerun directly.
    - **(b) Zero Unlabeled Synthetic Telemetry or Numbers:** Never generate synthetic telemetry, simulated numbers, or random draws in evaluation code without an explicit approval entry in `docs/APPROVAL_QUEUE.md`, a prominent `SIMULATED` label in file names and reports, and isolated, separate reporting.
    - **(c) Zero Metadata Leakage in Events & Features:** Scenario names, threat classes, and run IDs must **never** appear inside any telemetry event, fact dictionary, or feature representation consumed by classifiers.
    - **(d) Command Traceability:** Every factual claim in a gate report must explicitly name the exact shell or cluster command that proves it.

## AI-Assistance Disclosure Line for Final Report
```markdown
*AI Assistance Disclosure:* In accordance with academic integrity guidelines, generative AI tools (Antigravity) were utilized under Mode A pair programming: the AI assistant authored implementation code, test suites, configurations, and automation scripts under direct human direction, review, and specification. All phase gate verification tests were executed, inspected, and approved directly by the authors, who conducted all laboratory cluster experiments and retain full scientific and operational governance.
```
