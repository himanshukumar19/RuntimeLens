# RuntimeLens

Context-Aware Runtime and Orchestration Threat Classification for Multi-Tenant Kubernetes Using a Typed-Decision Model.

## Overview

RuntimeLens correlates multi-source container telemetry (Falco eBPF syscalls, Kubernetes API audit logs, Cilium/Hubble network flows, Prometheus resource metrics, and Trivy static image scans) with declarative workload baselines. State is evaluated by a constrained typed-decision model (ScaleDown Classify-1 via Decisions API) and governed by a pure deterministic safety policy engine.

## Prerequisites

- Python 3.12+
- `uv` package manager (`>=0.11`)
- macOS (development & CI) / Ubuntu 24.04 ARM64 VM (Kubernetes lab & eBPF)
- `kind`, `cilium-cli`, `kubectl`

## Quickstart

```bash
# Set up development virtual environment and install all dependencies
make setup

# Run linters and code formatters
make lint

# Run type checker
make typecheck

# Run unit tests
make test
```

## AI Assistance Disclosure

*In accordance with academic integrity guidelines, generative AI tools (Antigravity) were utilized under Mode A pair programming: the AI assistant authored implementation code, test suites, configurations, and automation scripts under direct human direction, review, and specification. All phase gate verification tests were executed, inspected, and approved directly by the authors, who conducted all laboratory cluster experiments and retain full scientific and operational governance.*
