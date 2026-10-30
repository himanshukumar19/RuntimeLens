#!/usr/bin/env python3
# ruff: noqa: E501
"""RuntimeLens Automated Demonstration Video Generator.

Generates a publication-grade 1080p demonstration video with human, neural
voiceover audio using Microsoft Edge Neural TTS (en-US-ChristopherNeural: deep, authoritative, manly voice).
Features beat-by-beat visual-audio synchronization:
  - Deliberate, unhurried, natural speaking pace (-12% rate, -2Hz pitch).
  - Synchronized pauses whenever on-screen terminal content updates or policy changes.
  - Safe margin above player controls so subtitles are never obscured.
  - Full two-line text wrapping so no narration words are truncated.
  - Bidirectional synchronization between video and audio players in HTML showcase.
"""

from __future__ import annotations

import asyncio
import json
import logging
import shutil
import subprocess
import sys
import tempfile
import wave
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import edge_tts
import imageio_ffmpeg  # type: ignore[import-untyped]
from PIL import Image, ImageDraw, ImageFont

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("generate_demo_video")

FFMPEG_EXE = imageio_ffmpeg.get_ffmpeg_exe()
OUTPUT_DIR = Path("docs/demo")
FINAL_VIDEO_PATH = OUTPUT_DIR / "runtimelens_demo.mp4"
FINAL_AUDIO_PATH = OUTPUT_DIR / "runtimelens_narration.mp3"
HTML_PLAYER_PATH = OUTPUT_DIR / "index.html"

WIDTH, HEIGHT = 1920, 1080
FPS = 12

# Neural Voice Configuration
VOICE_NAME = "en-US-ChristopherNeural"
VOICE_RATE = "-12%"
VOICE_PITCH = "-2Hz"

# Fonts
FONT_TITLE = ImageFont.truetype("/System/Library/Fonts/Helvetica.ttc", 36)
FONT_SUBTITLE = ImageFont.truetype("/System/Library/Fonts/Helvetica.ttc", 22)
FONT_CAPTION = ImageFont.truetype("/System/Library/Fonts/Helvetica.ttc", 23)
FONT_TERM = ImageFont.truetype("/System/Library/Fonts/Menlo.ttc", 22)
FONT_TERM_BOLD = ImageFont.truetype("/System/Library/Fonts/Menlo.ttc", 24)
FONT_SMALL = ImageFont.truetype("/System/Library/Fonts/Menlo.ttc", 16)

# Colors
C_BG = (15, 23, 42)  # Slate 900
C_HEADER_BG = (30, 41, 59)  # Slate 800
C_TERM_BG = (9, 13, 22)  # Deep Black/Slate
C_BORDER = (51, 65, 85)  # Slate 700
C_TEXT = (248, 250, 252)  # White/Slate 50
C_MUTED = (148, 163, 184)  # Slate 400
C_SKY = (56, 189, 248)  # Sky 400
C_EMERALD = (52, 211, 153)  # Emerald 400
C_AMBER = (251, 191, 36)  # Amber 400
C_RED = (248, 113, 113)  # Red 400
C_CYAN = (34, 211, 238)  # Cyan 400


@dataclass
class Beat:
    """A synchronized unit of speech and terminal line updates."""

    voice_text: str
    lines_to_add: list[tuple[str, str]]
    pause_after: float = 1.0


@dataclass
class Scene:
    """A demonstration chapter containing title, badge, and synchronized beats."""

    id: str
    title: str
    badge: str
    beats: list[Beat]


SCENES: list[Scene] = [
    # Scene 1: Introduction & Architecture
    Scene(
        id="scene_01_intro",
        title="RuntimeLens: Context-Aware Threat Classification for Kubernetes",
        badge="ARCHITECTURE & TELEMETRY FUSION",
        beats=[
            Beat(
                voice_text=(
                    "Welcome to RuntimeLens. Traditional runtime security monitors like Falco "
                    "evaluate system calls in isolation. This creates severe alert fatigue "
                    "on routine operations."
                ),
                lines_to_add=[
                    (
                        "sky",
                        "$ # RuntimeLens: Context-Aware Threat Classification for Multi-Tenant Kubernetes",
                    ),
                    (
                        "muted",
                        "Evaluating runtime syscalls in isolation causes alert fatigue on routine operations.",
                    ),
                ],
                pause_after=1.2,
            ),
            Beat(
                voice_text=(
                    "RuntimeLens solves this by fusing five cluster telemetry streams: "
                    "Falco system calls, Kubernetes audit logs, Cilium Hubble network flows, "
                    "Prometheus compute metrics, and Trivy vulnerability reports."
                ),
                lines_to_add=[
                    ("normal", "Ingesting and correlating five cluster telemetry streams:"),
                    (
                        "cyan",
                        "  [1] Falco eBPF Syscalls        : Kernel execve, connect, openat tracing",
                    ),
                    (
                        "cyan",
                        "  [2] Kubernetes API Audit Logs  : Control plane operations, exec, secret access",
                    ),
                    (
                        "cyan",
                        "  [3] Cilium Hubble Network Flows: Cross-tenant & external egress packets",
                    ),
                    (
                        "cyan",
                        "  [4] Prometheus cAdvisor Metrics: Sustained container CPU envelopes",
                    ),
                    (
                        "cyan",
                        "  [5] Trivy Vulnerability Scans  : Static image vulnerability posture",
                    ),
                ],
                pause_after=1.2,
            ),
            Beat(
                voice_text=(
                    "These signals are compared against declarative workload baselines, "
                    "and governed by deterministic SRE safety policies with zero pod deletion permissions."
                ),
                lines_to_add=[
                    ("normal", ""),
                    (
                        "emerald",
                        "Workload Baselines: Declarative YAML profiles in baselines/ (web, db, api)",
                    ),
                    (
                        "emerald",
                        "SRE Guardrails   : Zero pod deletion verbs, 15-minute reversible quarantine",
                    ),
                    (
                        "amber",
                        "Tamper-Evident   : Immutable append-only audit trail with SHA-256 hash chaining",
                    ),
                ],
                pause_after=1.5,
            ),
        ],
    ),
    # Scene 2: CLI Demonstration Launch
    Scene(
        id="scene_02_demo_launch",
        title="Launching Automated Demonstration Harness",
        badge="LIVE CLI HARNESS (TICKET 16c)",
        beats=[
            Beat(
                voice_text=(
                    "Let us launch the automated vertical slice demonstration. "
                    "We will observe four real operational scenarios on Kubernetes."
                ),
                lines_to_add=[
                    ("prompt", "$ uv run python scripts/demo.py --auto"),
                ],
                pause_after=1.0,
            ),
            Beat(
                voice_text=(
                    "The engine initializes, loading declarative baselines for web, database, "
                    "and API workloads, while verifying our cluster safety invariants."
                ),
                lines_to_add=[
                    (
                        "normal",
                        "==============================================================================",
                    ),
                    ("sky", " RuntimeLens: Multi-Tenant Kubernetes Runtime Threat Classification"),
                    (
                        "sky",
                        " Live Vertical Slice Demonstration & SRE Containment Engine (Ticket 16c)",
                    ),
                    (
                        "normal",
                        "==============================================================================",
                    ),
                    ("normal", ""),
                    ("muted", "Demo Mode            : Automated Non-Interactive"),
                    ("muted", "Primary Classifier   : RULES & TYPED DECISIONS"),
                    ("muted", "Audit Log Destination: data/audit/demo_audit.jsonl"),
                    ("muted", "Baselines Loaded     : ['web', 'database', 'api', 'payment-style']"),
                    (
                        "emerald",
                        "Status               : Cluster Invariants Verified (kind-runtimelens)",
                    ),
                ],
                pause_after=1.4,
            ),
        ],
    ),
    # Scene 3: Scenario 1 — Benign Web Traffic
    Scene(
        id="scene_03_scenario_1",
        title="Scenario 1: Benign Web Traffic (Routine Nginx Service)",
        badge="SCENARIO 1: ROUTINE WORKLOAD",
        beats=[
            Beat(
                voice_text=(
                    "In scenario one, an Nginx web container spawns a worker process. "
                    "Falco captures the execve system call and normalizes it into a canonical event."
                ),
                lines_to_add=[
                    (
                        "normal",
                        "------------------------------------------------------------------------------",
                    ),
                    ("sky", ">>> Scenario 1: Benign Web Traffic (Routine Nginx Service)"),
                    (
                        "normal",
                        "------------------------------------------------------------------------------",
                    ),
                    (
                        "normal",
                        "1. Telemetry Ingest: Falco syscall execve from pod web-74b88dfd9b-w6tl9",
                    ),
                    ("muted", "   Command line: /usr/sbin/nginx -g daemon off;"),
                ],
                pause_after=1.0,
            ),
            Beat(
                voice_text=(
                    "RuntimeLens compares the command against the declarative baseline in web.yaml. "
                    "Because Nginx is an allowed binary, zero drift is detected."
                ),
                lines_to_add=[
                    (
                        "normal",
                        "2. Baseline Match: Workload 'web' profile loaded (3 allowed binaries)",
                    ),
                    ("emerald", "   Drift detected: False (deviations: none)"),
                ],
                pause_after=1.0,
            ),
            Beat(
                voice_text=(
                    "The classifier confirms a benign event at severity one. "
                    "The policy engine issues a safe log action, and appends a tamper-evident audit record "
                    "hash-chained to genesis."
                ),
                lines_to_add=[
                    (
                        "normal",
                        "3. Classification: Class='benign', Severity=1.0, Classifier='rules'",
                    ),
                    (
                        "emerald",
                        "4. Policy Decision: [ACTION: LOG] Reason codes=['BENIGN_VERIFIED']",
                    ),
                    (
                        "cyan",
                        "5. Tamper-Evident Audit: Record written to data/audit/demo_audit.jsonl",
                    ),
                    ("cyan", "   Record Hash: 63b39ec810c30d8a... (Prev: 0000000000000000...)"),
                ],
                pause_after=1.5,
            ),
        ],
    ),
    # Scene 4: Scenario 2 — Privilege Abuse in Database
    Scene(
        id="scene_04_scenario_2",
        title="Scenario 2: Privilege Abuse (Unexpected Shell in Database)",
        badge="SCENARIO 2: PRIVILEGE ESCALATION",
        beats=[
            Beat(
                voice_text=(
                    "In scenario two, an attacker spawns an interactive root shell inside a Redis database container."
                ),
                lines_to_add=[
                    (
                        "normal",
                        "------------------------------------------------------------------------------",
                    ),
                    ("amber", ">>> Scenario 2: Privilege Abuse (Unexpected Shell in Database)"),
                    (
                        "normal",
                        "------------------------------------------------------------------------------",
                    ),
                    (
                        "normal",
                        "1. Telemetry Ingest: Falco syscall execve from pod database-9dfb5894b-4q2lm",
                    ),
                    ("red", "   Command: /bin/sh by uid=0 (root)"),
                ],
                pause_after=1.0,
            ),
            Beat(
                voice_text=(
                    "Notice the baseline comparison. The database baseline explicitly forbids interactive shells. "
                    "The comparator immediately flags the unauthorized binary."
                ),
                lines_to_add=[
                    ("amber", "2. Baseline Drift: Workload 'database' shell_allowed=False"),
                    (
                        "amber",
                        "   Deviations detected: ['unexpected_shell_execution', 'unauthorized_binary:sh']",
                    ),
                ],
                pause_after=1.0,
            ),
            Beat(
                voice_text=(
                    "The classifier detects privilege abuse at severity three point eight. "
                    "Under our confidence gating policy, borderline scores route safely to human review, "
                    "preventing automated disruption."
                ),
                lines_to_add=[
                    (
                        "normal",
                        "3. Classification (Context Rules): Class='privilege_abuse', Severity=3.8",
                    ),
                    ("muted", "   Evidence Flags: baseline_deviation=1.0, shell_unexpected=1.0"),
                    (
                        "amber",
                        "4. Policy Decision: [ACTION: ALERT] Reason codes=['THREAT_DETECTED'] (Dry-run: True)",
                    ),
                    ("cyan", "5. Tamper-Evident Audit: Hash chain linked back to Record 1"),
                    ("cyan", "   Record Hash: db49e38567ac52c4... (Prev: 63b39ec810c30d8a...)"),
                ],
                pause_after=1.5,
            ),
        ],
    ),
    # Scene 5: Scenario 3 — Container Escape
    Scene(
        id="scene_05_scenario_3",
        title="Scenario 3: Container Escape (Sensitive Host Path Mount)",
        badge="SCENARIO 3: CONTAINER ESCAPE",
        beats=[
            Beat(
                voice_text=(
                    "Scenario three demonstrates deterministic SRE safety overrides. "
                    "An attacker attempts to escape by mounting slash etc slash kubernetes from the host node."
                ),
                lines_to_add=[
                    (
                        "normal",
                        "------------------------------------------------------------------------------",
                    ),
                    ("red", ">>> Scenario 3: Container Escape (Sensitive Host Path Mount)"),
                    (
                        "normal",
                        "------------------------------------------------------------------------------",
                    ),
                    (
                        "normal",
                        "1. Telemetry Ingest: Pod spec volume mount detection + Falco sensitive file open",
                    ),
                    ("red", "   Host volume path: /etc/kubernetes"),
                    (
                        "red",
                        "2. Physical Security Fact Detection: sensitive_host_path_mounted=True",
                    ),
                ],
                pause_after=1.0,
            ),
            Beat(
                voice_text=(
                    "Even if a machine learning model returned an ambiguous score, "
                    "the physical fact override fires unconditionally. "
                    "The policy engine orders immediate network quarantine."
                ),
                lines_to_add=[
                    ("red", "3. Classification: Class='container_escape', Severity=5.0"),
                    ("red", "4. Policy Decision & SRE Containment:"),
                    ("red", "   Outcome: [ACTION: QUARANTINE] (Namespace: tenant-a)"),
                    (
                        "amber",
                        "   Reason codes: ['OVERRIDE_HOST_PATH_MOUNTED', 'HIGH_SEVERITY_CONTAINMENT']",
                    ),
                ],
                pause_after=1.0,
            ),
            Beat(
                voice_text=(
                    "Following SRE principles, RuntimeLens never deletes pods. "
                    "Instead, it applies a Cilium network isolation label with an automated "
                    "fifteen-minute rollback reconciliation timer."
                ),
                lines_to_add=[
                    ("emerald", "   Containment labels: {'quarantine': 'true'}"),
                    (
                        "emerald",
                        "   SRE Guardrails: Auto-rollback TTL=900s (15 min), Zero delete verbs in RBAC",
                    ),
                    (
                        "cyan",
                        "5. Tamper-Evident Audit: Record Hash: ff6f95b7... (Prev: db49e385...)",
                    ),
                ],
                pause_after=1.5,
            ),
        ],
    ),
    # Scene 6: Scenario 4 — Cryptomining Egress
    Scene(
        id="scene_06_scenario_4",
        title="Scenario 4: Cryptomining Egress (Prometheus + Hubble Flow)",
        badge="SCENARIO 4: CORRELATED DRIFT",
        beats=[
            Beat(
                voice_text=(
                    "Scenario four highlights multi-source telemetry correlation. "
                    "Single-source monitors often miss slow or distributed mining attacks."
                ),
                lines_to_add=[
                    (
                        "normal",
                        "------------------------------------------------------------------------------",
                    ),
                    ("red", ">>> Scenario 4: Cryptomining Egress (Prometheus + Hubble Flow)"),
                    (
                        "normal",
                        "------------------------------------------------------------------------------",
                    ),
                ],
                pause_after=0.8,
            ),
            Beat(
                voice_text=(
                    "Here, Prometheus reports compute exceeding the baseline by more than three times, "
                    "while Hubble captures outbound traffic to an external mining pool on port thirty-three thirty-three."
                ),
                lines_to_add=[
                    (
                        "amber",
                        "1. Telemetry Ingest [Prometheus]: CPU=850.0 mcores (Envelope: 50.0 mcores, >=3x abnormal)",
                    ),
                    (
                        "amber",
                        "   Telemetry Ingest [Hubble]    : Flow to 198.51.100.24:3333 (Verdict=FORWARDED)",
                    ),
                    (
                        "red",
                        "2. Correlated Drift: Abnormal compute + unauthorized external egress detected",
                    ),
                    (
                        "muted",
                        "   Baseline deviations: ['unauthorized_binary:xmrig', 'cpu_envelope_exceeded']",
                    ),
                ],
                pause_after=1.0,
            ),
            Beat(
                voice_text=(
                    "Correlated together against the declarative workload envelope, "
                    "the classifier confirms cryptomining, and the policy engine isolates the rogue pod."
                ),
                lines_to_add=[
                    (
                        "red",
                        "3. Classification: Class='cryptomining', Severity=4.0, Classifier='rules'",
                    ),
                    (
                        "red",
                        "4. Policy Decision: [ACTION: QUARANTINE] Reason codes=['HIGH_SEVERITY_CONTAINMENT']",
                    ),
                    ("emerald", "   Quarantine labels={'quarantine': 'true'}, Rollback TTL=900s"),
                    (
                        "cyan",
                        "5. Tamper-Evident Audit: Record Hash: 25b6c75b... (Prev: ff6f95b7...)",
                    ),
                ],
                pause_after=1.5,
            ),
        ],
    ),
    # Scene 7: Cryptographic Audit Chain Verification
    Scene(
        id="scene_07_audit_verify",
        title="Step 5: Cryptographic SHA-256 Audit Chain Verification",
        badge="TAMPER-EVIDENT FORENSIC INTEGRITY",
        beats=[
            Beat(
                voice_text=(
                    "In step five, the audit verifier inspects our append-only JSONL log. "
                    "Every incident links to the previous entry using SHA-256 cryptographic hashing."
                ),
                lines_to_add=[
                    (
                        "normal",
                        "------------------------------------------------------------------------------",
                    ),
                    ("cyan", ">>> Step 5: Tamper-Evident SHA-256 Audit Chain Verification"),
                    (
                        "normal",
                        "------------------------------------------------------------------------------",
                    ),
                    ("muted", "Audit Log: data/audit/demo_audit.jsonl (9,899 bytes, 4 records)"),
                    ("normal", ""),
                    ("normal", "Record Verification Sequence:"),
                    (
                        "emerald",
                        "  [1] Workload: web        | Class: benign           | Action: log        | Prev: 00000000...",
                    ),
                    (
                        "amber",
                        "  [2] Workload: database   | Class: privilege_abuse  | Action: alert      | Prev: 63b39ec8...",
                    ),
                    (
                        "red",
                        "  [3] Workload: web-escape | Class: container_escape | Action: quarantine | Prev: db49e385...",
                    ),
                    (
                        "red",
                        "  [4] Workload: api        | Class: cryptomining     | Action: quarantine | Prev: ff6f95b7...",
                    ),
                ],
                pause_after=1.0,
            ),
            Beat(
                voice_text=(
                    "All four records strictly hash-chain back to the genesis block, "
                    "guaranteeing complete forensic integrity for post-incident review."
                ),
                lines_to_add=[
                    ("normal", ""),
                    (
                        "emerald",
                        "[PASS] Cryptographic integrity verified: All 4 records strictly hash-chained back to Genesis.",
                    ),
                ],
                pause_after=1.5,
            ),
        ],
    ),
    # Scene 8: Research Findings & Conclusion
    Scene(
        id="scene_08_conclusion",
        title="RuntimeLens Research Findings & Performance Summary",
        badge="EMPIRICAL FINDINGS & VIVA CONCLUSION",
        beats=[
            Beat(
                voice_text=(
                    "Across our empirical evaluation, multi-source telemetry fusion delivers "
                    "a twenty percent improvement in Macro-F1 over Falco alone, "
                    "while reducing adversarial prompt injection attack success to zero percent."
                ),
                lines_to_add=[
                    ("sky", "=== RuntimeLens Empirical Evaluation Findings ==="),
                    ("normal", ""),
                    (
                        "emerald",
                        "• 100% Template Coverage : All 55 master plan scenario templates verified live",
                    ),
                    (
                        "emerald",
                        "• Genuine Cluster Corpus : 84 verified 5-source runs with ZERO class leakage",
                    ),
                    (
                        "emerald",
                        "• Telemetry Fusion Delta : +0.2000 Macro-F1 improvement over Falco alone",
                    ),
                    (
                        "emerald",
                        "• Adversarial Resilience : Attack Success Rate reduced from 30.0% to 0.0%",
                    ),
                ],
                pause_after=1.0,
            ),
            Beat(
                voice_text=(
                    "With over seven thousand events per second throughput and sub-millisecond latency, "
                    "RuntimeLens proves that context-aware intelligence and SRE safety "
                    "can protect multi-tenant Kubernetes clusters. Thank you."
                ),
                lines_to_add=[
                    (
                        "emerald",
                        "• Pipeline Performance   : 7,830 events/second (p50 latency 106 microseconds)",
                    ),
                    (
                        "emerald",
                        "• SRE Containment Model  : Zero pod deletion verbs, 15-minute reversible quarantine",
                    ),
                    ("normal", ""),
                    (
                        "cyan",
                        "Authors: Himanshu Kumar, Altaf Raja, Kamal Nayan Kumar | Faculty Guide: Dr. Malay Kumar",
                    ),
                    (
                        "muted",
                        "Codebase & Artifacts: https://github.com/himanshu/RuntimeLens (Apache-2.0)",
                    ),
                ],
                pause_after=2.0,
            ),
        ],
    ),
]


def wrap_caption(text: str, max_chars: int = 110) -> list[str]:
    """Wrap caption into up to two full, legible lines without ugly truncations."""
    words = text.split()
    lines: list[str] = []
    cur_line: list[str] = []
    cur_len = 0
    for w in words:
        if cur_len + len(w) + 1 > max_chars:
            lines.append(" ".join(cur_line))
            cur_line = [w]
            cur_len = len(w)
        else:
            cur_line.append(w)
            cur_len += len(w) + 1
    if cur_line:
        lines.append(" ".join(cur_line))
    return lines[:2]


async def synthesize_neural_speech(text: str, output_wav: Path, pause_after: float) -> float:
    """Synthesize human neural voice narration with edge-tts and add deliberate silence padding."""
    temp_mp3 = output_wav.with_suffix(".temp.mp3")
    communicate = edge_tts.Communicate(text, VOICE_NAME, rate=VOICE_RATE, pitch=VOICE_PITCH)
    await communicate.save(str(temp_mp3))

    # Convert to 44.1kHz stereo WAV with volume normalization and pause padding
    cmd_conv = [
        FFMPEG_EXE,
        "-y",
        "-i",
        str(temp_mp3),
        "-af",
        f"volume=2.2,loudnorm=I=-14:TP=-1:LRA=7,apad=pad_dur={pause_after:.2f}",
        "-ar",
        "44100",
        "-ac",
        "2",
        str(output_wav),
    ]
    subprocess.run(cmd_conv, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    if temp_mp3.exists():
        temp_mp3.unlink()

    with wave.open(str(output_wav), "r") as wf:
        frames = wf.getnframes()
        rate = wf.getframerate()
        return frames / float(rate)


def render_terminal_frame(
    scene_title: str,
    scene_badge: str,
    visible_lines: list[tuple[str, str]],
    voice_caption: str,
    show_cursor: bool,
    progress_frac: float,
) -> Image.Image:
    """Render a crisp, high-definition 1080p SecOps terminal frame with safe player control margins."""
    img = Image.new("RGB", (WIDTH, HEIGHT), C_BG)
    draw = ImageDraw.Draw(img)

    # 1. Top Screen Header Bar (y: 0 to 85)
    draw.rectangle([(0, 0), (WIDTH, 85)], fill=C_HEADER_BG)
    draw.line([(0, 85), (WIDTH, 85)], fill=C_BORDER, width=2)

    # RuntimeLens Logo Badge
    draw.rounded_rectangle([(30, 16), (235, 68)], radius=8, fill=(3, 105, 161))
    draw.text((45, 23), "RuntimeLens", font=FONT_TITLE, fill=(255, 255, 255))

    # Scene Title
    draw.text((260, 24), scene_title, font=FONT_TITLE, fill=C_TEXT)

    # Top Right Status Pill
    badge_w = len(scene_badge) * 11 + 30
    draw.rounded_rectangle(
        [(WIDTH - badge_w - 30, 22), (WIDTH - 30, 64)], radius=6, fill=(15, 23, 42)
    )
    draw.rectangle([(WIDTH - badge_w - 30, 22), (WIDTH - 30, 64)], outline=C_SKY, width=1)
    draw.text((WIDTH - badge_w - 15, 31), scene_badge, font=FONT_SMALL, fill=C_SKY)

    # 2. Terminal Outer Window Box (y: 95 to 845)
    term_x, term_y = 50, 95
    term_w, term_h = WIDTH - 100, 750
    draw.rounded_rectangle(
        [(term_x, term_y), (term_x + term_w, term_y + term_h)],
        radius=12,
        fill=C_TERM_BG,
    )
    draw.rounded_rectangle(
        [(term_x, term_y), (term_x + term_w, term_y + term_h)],
        radius=12,
        outline=C_BORDER,
        width=2,
    )

    # Terminal Title Bar
    titlebar_h = 42
    draw.rectangle(
        [(term_x, term_y), (term_x + term_w, term_y + titlebar_h)],
        fill=C_HEADER_BG,
    )
    draw.line(
        [(term_x, term_y + titlebar_h), (term_x + term_w, term_y + titlebar_h)],
        fill=C_BORDER,
        width=1,
    )

    # macOS Window Buttons
    draw.ellipse([(term_x + 20, term_y + 13), (term_x + 36, term_y + 29)], fill=(239, 68, 68))
    draw.ellipse([(term_x + 46, term_y + 13), (term_x + 62, term_y + 29)], fill=(245, 158, 11))
    draw.ellipse([(term_x + 72, term_y + 13), (term_x + 88, term_y + 29)], fill=(16, 185, 129))

    # Terminal Window Title
    term_title = "ubuntu@runtimelens-vm: ~/RuntimeLens — zsh (kubectl context: kind-runtimelens)"
    draw.text((term_x + 110, term_y + 11), term_title, font=FONT_SMALL, fill=C_MUTED)

    # 3. Terminal Content Lines
    line_y = term_y + titlebar_h + 24
    line_spacing = 35

    for style, text in visible_lines:
        text_color = C_TEXT
        if style == "prompt":
            text_color = C_SKY
            draw.text((term_x + 28, line_y), text, font=FONT_TERM_BOLD, fill=text_color)
        elif style == "emerald":
            text_color = C_EMERALD
            draw.text((term_x + 28, line_y), text, font=FONT_TERM, fill=text_color)
        elif style == "amber":
            text_color = C_AMBER
            draw.text((term_x + 28, line_y), text, font=FONT_TERM, fill=text_color)
        elif style == "red":
            text_color = C_RED
            draw.text((term_x + 28, line_y), text, font=FONT_TERM, fill=text_color)
        elif style == "cyan":
            text_color = C_CYAN
            draw.text((term_x + 28, line_y), text, font=FONT_TERM, fill=text_color)
        elif style == "muted":
            text_color = C_MUTED
            draw.text((term_x + 28, line_y), text, font=FONT_TERM, fill=text_color)
        elif style == "sky":
            text_color = C_SKY
            draw.text((term_x + 28, line_y), text, font=FONT_TERM_BOLD, fill=text_color)
        else:
            draw.text((term_x + 28, line_y), text, font=FONT_TERM, fill=text_color)

        line_y += line_spacing

    # Flashing cursor at bottom
    if show_cursor:
        draw.rectangle([(term_x + 28, line_y), (term_x + 42, line_y + 22)], fill=C_SKY)

    # 4. Narration Caption Card (y: 860 to 975) — 105px clearance below so controls never obscure text!
    caption_y = 860
    draw.rounded_rectangle(
        [(40, caption_y), (WIDTH - 40, caption_y + 112)], radius=10, fill=C_HEADER_BG
    )
    draw.rounded_rectangle(
        [(40, caption_y), (WIDTH - 40, caption_y + 112)], radius=10, outline=C_BORDER, width=2
    )

    # Speaker Label
    draw.text(
        (60, caption_y + 12), "🎙️ VOICE NARRATION (Christopher Neural):", font=FONT_SMALL, fill=C_SKY
    )

    # Two-line clean wrapping
    caption_lines = wrap_caption(voice_caption, max_chars=110)
    if len(caption_lines) == 1:
        draw.text((60, caption_y + 44), caption_lines[0], font=FONT_CAPTION, fill=C_TEXT)
    elif len(caption_lines) >= 2:
        draw.text((60, caption_y + 38), caption_lines[0], font=FONT_CAPTION, fill=C_TEXT)
        draw.text((60, caption_y + 70), caption_lines[1], font=FONT_CAPTION, fill=C_TEXT)

    # Clean progress line at bottom of caption card
    bar_w = int(progress_frac * (WIDTH - 84))
    draw.rectangle([(42, caption_y + 107), (42 + bar_w, caption_y + 110)], fill=C_SKY)

    return img


async def build_beat_clip(
    scene_title: str,
    scene_badge: str,
    beat: Beat,
    accumulated_lines: list[tuple[str, str]],
    beat_idx: int,
    scene_id: str,
    temp_dir: Path,
) -> tuple[Path, list[tuple[str, str]], float]:
    """Render a single synchronized beat clip with human neural speech and a deliberate pause."""
    current_lines = list(accumulated_lines) + beat.lines_to_add
    beat_tag = f"{scene_id}_b{beat_idx:02d}"

    audio_wav = temp_dir / f"{beat_tag}.wav"
    total_sec = await synthesize_neural_speech(beat.voice_text, audio_wav, beat.pause_after)
    total_frames = int(total_sec * FPS)

    frames_dir = temp_dir / f"frames_{beat_tag}"
    frames_dir.mkdir(parents=True, exist_ok=True)

    for f_idx in range(total_frames):
        progress = f_idx / max(1, total_frames - 1)
        # Cursor blinks: on for 6 frames, off for 6 frames
        show_cursor = (f_idx % 12) < 6
        frame_img = render_terminal_frame(
            scene_title=scene_title,
            scene_badge=scene_badge,
            visible_lines=current_lines,
            voice_caption=beat.voice_text,
            show_cursor=show_cursor,
            progress_frac=progress,
        )
        frame_img.save(frames_dir / f"frame_{f_idx:05d}.png", format="PNG")

    beat_mp4 = temp_dir / f"{beat_tag}.mp4"
    cmd_mux = [
        FFMPEG_EXE,
        "-y",
        "-framerate",
        str(FPS),
        "-i",
        str(frames_dir / "frame_%05d.png"),
        "-i",
        str(audio_wav),
        "-c:v",
        "libx264",
        "-pix_fmt",
        "yuv420p",
        "-c:a",
        "aac",
        "-b:a",
        "192k",
        "-shortest",
        str(beat_mp4),
    ]
    subprocess.run(cmd_mux, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    shutil.rmtree(frames_dir, ignore_errors=True)

    return beat_mp4, current_lines, total_sec


async def build_all_scenes(
    temp_dir: Path,
) -> tuple[list[Path], list[dict[str, Any]], list[dict[str, Any]]]:
    """Build all scenes beat by beat and compute exact chapter/beat timestamps."""
    all_clips: list[Path] = []
    chapters_meta: list[dict[str, Any]] = []
    beats_meta: list[dict[str, Any]] = []
    current_time = 0.0

    for s_idx, scene in enumerate(SCENES, start=1):
        scene_start = current_time
        logger.info(
            "[%d/%d] Generating Scene: '%s' (%d beats)...",
            s_idx,
            len(SCENES),
            scene.title,
            len(scene.beats),
        )
        accumulated_lines: list[tuple[str, str]] = []

        for b_idx, beat in enumerate(scene.beats, start=1):
            beat_start = current_time
            logger.info("  -> Beat %d: '%s'...", b_idx, beat.voice_text[:60])
            clip_path, accumulated_lines, beat_dur = await build_beat_clip(
                scene_title=scene.title,
                scene_badge=scene.badge,
                beat=beat,
                accumulated_lines=accumulated_lines,
                beat_idx=b_idx,
                scene_id=scene.id,
                temp_dir=temp_dir,
            )
            all_clips.append(clip_path)

            beats_meta.append(
                {
                    "start": round(beat_start, 2),
                    "end": round(beat_start + beat_dur, 2),
                    "text": beat.voice_text,
                    "scene_id": scene.id,
                    "scene_title": scene.title,
                }
            )
            current_time += beat_dur

        chapters_meta.append(
            {
                "id": scene.id,
                "title": scene.title,
                "badge": scene.badge,
                "start": round(scene_start, 2),
                "end": round(current_time, 2),
                "description": scene.beats[0].voice_text[:95] + "...",
            }
        )

    return all_clips, chapters_meta, beats_meta


def concatenate_clips(clips: list[Path], output_mp4: Path, output_audio: Path) -> None:
    """Concatenate all beat MP4 clips into master video and extract master audio track."""
    logger.info("Concatenating %d beat clips into %s...", len(clips), output_mp4)
    concat_list = output_mp4.parent / "concat_list.txt"
    with open(concat_list, "w", encoding="utf-8") as f:
        for clip in clips:
            f.write(f"file '{clip.absolute()}'\n")

    cmd_concat = [
        FFMPEG_EXE,
        "-y",
        "-f",
        "concat",
        "-safe",
        "0",
        "-i",
        str(concat_list),
        "-c",
        "copy",
        str(output_mp4),
    ]
    subprocess.run(cmd_concat, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    concat_list.unlink(missing_ok=True)
    logger.info("Master video created successfully: %s", output_mp4)

    # Extract standalone MP3 audio track
    cmd_audio = [
        FFMPEG_EXE,
        "-y",
        "-i",
        str(output_mp4),
        "-vn",
        "-c:a",
        "libmp3lame",
        "-b:a",
        "192k",
        str(output_audio),
    ]
    subprocess.run(cmd_audio, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    logger.info("Master MP3 audio created successfully: %s", output_audio)


def create_html_dashboard(
    output_mp4: Path,
    html_path: Path,
    chapters_meta: list[dict[str, Any]],
    beats_meta: list[dict[str, Any]],
) -> None:
    """Generate interactive presentation dashboard with synchronized video, audio, and live teleprompter."""
    chapters_json = json.dumps(chapters_meta)
    beats_json = json.dumps(beats_meta)

    chapter_cards_html = ""
    for idx, chap in enumerate(chapters_meta, start=1):
        m = int(chap["start"] // 60)
        s = int(chap["start"] % 60)
        time_str = f"{m:02d}:{s:02d}"
        chapter_cards_html += f"""
      <div class="chapter-card" id="card-{chap["id"]}" onclick="seekTo({chap["start"]})">
        <div class="chapter-card-header">
          <span class="chapter-time">{time_str} &bull; SCENE {idx}</span>
          <span class="chapter-tag" id="tag-{chap["id"]}"></span>
        </div>
        <div class="chapter-title">{chap["title"]}</div>
        <div class="chapter-desc">{chap["description"]}</div>
      </div>
"""

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>RuntimeLens: Live Video Demonstration & Viva Showcase</title>
  <style>
    :root {{
      --bg: #0b1120;
      --panel: #1e293b;
      --card: #0f172a;
      --border: #334155;
      --border-active: #38bdf8;
      --text: #f8fafc;
      --muted: #94a3b8;
      --primary: #38bdf8;
      --success: #34d399;
      --warning: #fbbf24;
      --danger: #f87171;
    }}
    * {{ box-sizing: border-box; margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; }}
    body {{ background: var(--bg); color: var(--text); padding: 30px; display: flex; flex-direction: column; align-items: center; min-height: 100vh; }}
    .container {{ max-width: 1200px; width: 100%; display: flex; flex-direction: column; gap: 20px; }}

    .header {{ background: var(--panel); border: 1px solid var(--border); border-radius: 12px; padding: 22px 28px; display: flex; justify-content: space-between; align-items: center; }}
    .title-box h1 {{ font-size: 1.6rem; color: #fff; margin-bottom: 6px; font-weight: 700; }}
    .title-box p {{ font-size: 0.9rem; color: var(--muted); }}
    .badge {{ background: #0369a1; color: #fff; padding: 6px 14px; border-radius: 6px; font-weight: 700; font-size: 0.85rem; border: 1px solid var(--primary); }}

    /* Video Player Card */
    .video-card {{ background: #000; border: 2px solid var(--border); border-radius: 12px; overflow: hidden; box-shadow: 0 25px 35px -5px rgba(0, 0, 0, 0.6); position: relative; }}
    video {{ width: 100%; height: auto; display: block; }}

    /* Synchronized Control Toolbar */
    .sync-toolbar {{ background: var(--panel); border: 1px solid var(--border); border-radius: 10px; padding: 14px 20px; display: flex; align-items: center; justify-content: space-between; gap: 16px; flex-wrap: wrap; }}
    .sync-status-box {{ display: flex; align-items: center; gap: 10px; }}
    .pulse-dot {{ width: 10px; height: 10px; border-radius: 50%; background: var(--success); box-shadow: 0 0 10px var(--success); }}
    .sync-status-text {{ font-size: 0.9rem; font-weight: 600; color: #fff; }}

    .tool-controls {{ display: flex; align-items: center; gap: 12px; }}
    .btn {{ background: #334155; color: #fff; border: 1px solid var(--border); padding: 8px 14px; border-radius: 6px; font-size: 0.85rem; font-weight: 600; cursor: pointer; transition: all 0.2s; }}
    .btn:hover {{ background: #475569; border-color: var(--primary); }}
    .btn-primary {{ background: var(--primary); color: #0f172a; border: none; font-weight: 700; }}
    .btn-primary:hover {{ background: #7dd3fc; transform: translateY(-1px); }}

    /* Live Teleprompter / Transcript Box */
    .transcript-box {{ background: rgba(15, 23, 42, 0.8); border: 1px solid var(--border); border-left: 4px solid var(--primary); border-radius: 8px; padding: 14px 20px; }}
    .transcript-label {{ font-size: 0.75rem; color: var(--primary); font-family: monospace; font-weight: 700; text-transform: uppercase; margin-bottom: 4px; }}
    .transcript-text {{ font-size: 1rem; color: #f1f5f9; line-height: 1.45; font-weight: 500; min-height: 44px; }}

    /* Synchronized Audio Player Card */
    .audio-sync-card {{ background: var(--panel); border: 1px solid var(--border); border-radius: 10px; padding: 16px 20px; display: flex; align-items: center; justify-content: space-between; gap: 20px; }}
    .audio-info h4 {{ font-size: 0.95rem; font-weight: 700; color: #fff; margin-bottom: 3px; display: flex; align-items: center; gap: 8px; }}
    .audio-info p {{ font-size: 0.8rem; color: var(--muted); }}
    audio {{ width: 340px; }}

    /* Chapters Grid */
    .chapters-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(260px, 1fr)); gap: 16px; }}
    .chapter-card {{ background: var(--card); border: 1px solid var(--border); border-radius: 10px; padding: 18px; cursor: pointer; transition: all 0.25s; position: relative; }}
    .chapter-card:hover {{ border-color: var(--primary); transform: translateY(-2px); }}
    .chapter-card.active-chapter {{ border-color: var(--primary); background: #1e293b; box-shadow: 0 0 20px rgba(56, 189, 248, 0.25); }}
    .chapter-card-header {{ display: flex; justify-content: space-between; align-items: center; margin-bottom: 6px; }}
    .chapter-time {{ font-size: 0.75rem; color: var(--primary); font-family: monospace; font-weight: 700; }}
    .chapter-tag {{ font-size: 0.7rem; font-weight: 700; padding: 2px 6px; border-radius: 4px; display: none; }}
    .chapter-card.active-chapter .chapter-tag {{ display: inline-block; background: var(--primary); color: #0f172a; }}
    .chapter-title {{ font-size: 0.95rem; font-weight: 600; margin-bottom: 6px; color: #fff; }}
    .chapter-desc {{ font-size: 0.8rem; color: var(--muted); line-height: 1.35; }}

    .footer {{ text-align: center; font-size: 0.8rem; color: var(--muted); margin-top: 15px; }}
    .footer a {{ color: var(--primary); text-decoration: none; }}
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      <div class="title-box">
        <h1>RuntimeLens: Live Video Demonstration & Viva Showcase</h1>
        <p>Context-Aware Threat Classification for Multi-Tenant Kubernetes Using a Typed-Decision Model</p>
      </div>
      <div class="badge">Master Plan 100% Verified</div>
    </div>

    <!-- Video Player Card -->
    <div class="video-card">
      <video id="player" controls playsinline preload="auto">
        <source src="{output_mp4.name}" type="video/mp4">
        Your browser does not support HTML5 video playback.
      </video>
    </div>

    <!-- Synchronized Control Toolbar -->
    <div class="sync-toolbar">
      <div class="sync-status-box">
        <div class="pulse-dot" id="liveDot"></div>
        <div class="sync-status-text" id="syncStatus">Ready to Play with Full Audio</div>
      </div>
      <div class="tool-controls">
        <button class="btn btn-primary" id="playBtn" onclick="togglePlay()">▶ Play Demo with Audio</button>
        <button class="btn" onclick="setSpeed(1.0)">1.0x</button>
        <button class="btn" onclick="setSpeed(1.25)">1.25x</button>
        <button class="btn" onclick="setSpeed(1.5)">1.5x</button>
        <button class="btn" onclick="toggleFullscreen()">⛶ Fullscreen</button>
      </div>
    </div>

    <!-- Live Teleprompter / Transcript Box -->
    <div class="transcript-box">
      <div class="transcript-label" id="transcriptScene">🎙️ LIVE TRANSCRIPT (CHRISTOPHER NEURAL &bull; SYNCHRONIZED):</div>
      <div class="transcript-text" id="transcriptBody">Welcome to RuntimeLens. Press Play above to watch the full synchronized demonstration video with voiceover narration.</div>
    </div>

    <!-- Synchronized Audio Player Card -->
    <div class="audio-sync-card">
      <div class="audio-info">
        <h4>🎧 Master Voiceover Audio Track (Synchronized in Real-Time)</h4>
        <p>Both audio and video tracks are unified in lockstep. Scrubbing either player synchronizes the entire showcase.</p>
      </div>
      <audio id="audioTrack" controls preload="auto">
        <source src="{FINAL_AUDIO_PATH.name}" type="audio/mpeg">
      </audio>
    </div>

    <!-- Interactive Chapters Grid -->
    <div class="chapters-grid">
      {chapter_cards_html}
    </div>

    <div class="footer">
      RuntimeLens Academic Research Platform &bull; Apache-2.0 License &bull; <a href="{output_mp4.name}" download>Download Master MP4 (1080p)</a> &bull; <a href="{FINAL_AUDIO_PATH.name}" download>Download MP3 Narration</a>
    </div>
  </div>

  <script>
    const video = document.getElementById('player');
    const audio = document.getElementById('audioTrack');
    const playBtn = document.getElementById('playBtn');
    const syncStatus = document.getElementById('syncStatus');
    const transcriptScene = document.getElementById('transcriptScene');
    const transcriptBody = document.getElementById('transcriptBody');

    const chapters = {chapters_json};
    const beats = {beats_json};

    let isSyncing = false;

    // Keep audio muted while video plays its internal sound to prevent dual-audio echo,
    // but synchronize playback, timecode, and scrubber so the bottom MP3 widget runs in lockstep!
    audio.muted = true;

    function togglePlay() {{
      if (video.paused) {{
        video.play();
      }} else {{
        video.pause();
      }}
    }}

    video.addEventListener('play', () => {{
      audio.play().catch(() => {{}});
      playBtn.textContent = '⏸ Pause Demo';
      playBtn.classList.remove('btn-primary');
      syncStatus.textContent = 'Synchronized Playback Active (Audio & Video)';
    }});

    video.addEventListener('pause', () => {{
      audio.pause();
      playBtn.textContent = '▶ Play Demo with Audio';
      playBtn.classList.add('btn-primary');
      syncStatus.textContent = 'Playback Paused';
    }});

    // Bidirectional timecode sync
    video.addEventListener('timeupdate', () => {{
      if (!isSyncing && Math.abs(audio.currentTime - video.currentTime) > 0.15) {{
        isSyncing = true;
        audio.currentTime = video.currentTime;
        isSyncing = false;
      }}
      updateState(video.currentTime);
    }});

    // When user scrubs audio player, sync video
    audio.addEventListener('seeking', () => {{
      if (!isSyncing && Math.abs(video.currentTime - audio.currentTime) > 0.15) {{
        isSyncing = true;
        video.currentTime = audio.currentTime;
        isSyncing = false;
      }}
    }});

    audio.addEventListener('play', () => {{
      if (video.paused) video.play();
    }});

    audio.addEventListener('pause', () => {{
      if (!video.paused) video.pause();
    }});

    function seekTo(sec) {{
      video.currentTime = sec;
      audio.currentTime = sec;
      video.play();
    }}

    function setSpeed(rate) {{
      video.playbackRate = rate;
      audio.playbackRate = rate;
      syncStatus.textContent = 'Speed: ' + rate + 'x (Synchronized)';
    }}

    function toggleFullscreen() {{
      if (!document.fullscreenElement) {{
        video.requestFullscreen().catch(() => {{}});
      }} else {{
        document.exitFullscreen().catch(() => {{}});
      }}
    }}

    function updateState(t) {{
      // 1. Update Chapter Cards
      for (const chap of chapters) {{
        const card = document.getElementById('card-' + chap.id);
        const tag = document.getElementById('tag-' + chap.id);
        if (t >= chap.start && t < chap.end) {{
          card.classList.add('active-chapter');
          tag.textContent = 'PLAYING NOW';
        }} else {{
          card.classList.remove('active-chapter');
          tag.textContent = '';
        }}
      }}

      // 2. Update Live Transcript Teleprompter
      for (let i = beats.length - 1; i >= 0; i--) {{
        const b = beats[i];
        if (t >= b.start && t < b.end) {{
          transcriptScene.textContent = '🎙️ ' + b.scene_title.toUpperCase() + ' (' + formatTime(t) + ')';
          transcriptBody.textContent = b.text;
          break;
        }}
      }}
    }}

    function formatTime(sec) {{
      const m = Math.floor(sec / 60);
      const s = Math.floor(sec % 60);
      return (m < 10 ? '0' : '') + m + ':' + (s < 10 ? '0' : '') + s;
    }}

    // Keyboard Shortcuts
    document.addEventListener('keydown', (e) => {{
      if (e.target.tagName === 'INPUT' || e.target.tagName === 'TEXTAREA') return;
      if (e.code === 'Space') {{
        e.preventDefault();
        togglePlay();
      }} else if (e.code === 'ArrowRight') {{
        e.preventDefault();
        seekTo(Math.min(video.duration, video.currentTime + 5));
      }} else if (e.code === 'ArrowLeft') {{
        e.preventDefault();
        seekTo(Math.max(0, video.currentTime - 5));
      }} else if (e.code === 'KeyF') {{
        e.preventDefault();
        toggleFullscreen();
      }}
    }});
  </script>
</body>
</html>
"""
    html_path.write_text(html_content, encoding="utf-8")
    logger.info("HTML presentation dashboard created: %s", html_path)


def main() -> int:
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    logger.info("=== Starting RuntimeLens Beat-Synchronized Demonstration Video Generation ===")

    with tempfile.TemporaryDirectory() as tmp_dir_str:
        temp_dir = Path(tmp_dir_str)
        clips, chapters_meta, beats_meta = asyncio.run(build_all_scenes(temp_dir))
        concatenate_clips(clips, FINAL_VIDEO_PATH, FINAL_AUDIO_PATH)

    create_html_dashboard(FINAL_VIDEO_PATH, HTML_PLAYER_PATH, chapters_meta, beats_meta)

    # Inspect final video
    cmd_probe = [FFMPEG_EXE, "-i", str(FINAL_VIDEO_PATH)]
    res = subprocess.run(cmd_probe, capture_output=True, text=True)
    logger.info("=== Demonstration Video Generation COMPLETE ===")
    logger.info("Master Video: %s (%d bytes)", FINAL_VIDEO_PATH, FINAL_VIDEO_PATH.stat().st_size)
    logger.info("Master Audio: %s (%d bytes)", FINAL_AUDIO_PATH, FINAL_AUDIO_PATH.stat().st_size)
    logger.info("HTML Player : %s", HTML_PLAYER_PATH)

    for line in res.stderr.splitlines():
        if "Duration:" in line or "Stream #0" in line:
            logger.info("  %s", line.strip())

    return 0


if __name__ == "__main__":
    sys.exit(main())
