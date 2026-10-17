"""Defense-in-depth sanitization and deterministic feature extraction for untrusted inputs."""

from __future__ import annotations

import hashlib
import unicodedata
from typing import Final

from pydantic import BaseModel, Field

MAX_SANITIZED_LENGTH: Final[int] = 128

SHELL_METACHARACTERS: Final[frozenset[str]] = frozenset("&|;$`><(){}\"'*\n\r\\")

SENSITIVE_PATTERNS: Final[tuple[str, ...]] = (
    "/var/run/docker.sock",
    "/var/run/containerd/containerd.sock",
    "/var/run/crio/crio.sock",
    "/run/containerd/containerd.sock",
    "/etc/shadow",
    "/etc/passwd",
    "/etc/kubernetes",
    "/proc/sys",
    "/sys/fs/cgroup",
    "/dev/mem",
    "/dev/kmem",
    "/root",
)

PROMPT_INJECTION_KEYWORDS: Final[tuple[str, ...]] = (
    "<untrusted_args>",
    "</untrusted_args>",
    "ignore previous instructions",
    "ignore all previous",
    "system prompt",
    "classified as benign",
    "classify as benign",
    "you must classify",
    "return choice: benign",
    "return benign",
    "treat this as benign",
    "override previous",
)

# Explicit set of zero-width and directional control code points
DISALLOWED_CODEPOINTS: Final[frozenset[int]] = frozenset(
    {
        0x200B,  # Zero-width space
        0x200C,  # Zero-width non-joiner
        0x200D,  # Zero-width joiner
        0x200E,  # Left-to-right mark
        0x200F,  # Right-to-left mark
        0x202A,  # Left-to-right embedding
        0x202B,  # Right-to-left embedding
        0x202C,  # Pop directional formatting
        0x202D,  # Left-to-right override
        0x202E,  # Right-to-left override
        0x2066,  # Left-to-right isolate
        0x2067,  # Right-to-left isolate
        0x2068,  # First strong isolate
        0x2069,  # Pop directional isolate
        0xFEFF,  # Zero-width no-break space / BOM
    }
)


class SanitizedInput(BaseModel):
    """Result of untrusted input sanitization and pre-truncation fact extraction."""

    sanitized_text: str = Field(
        ...,
        max_length=MAX_SANITIZED_LENGTH,
        description="Sanitized and truncated text string, safe for model prompt inclusion.",
    )
    raw_sha256: str = Field(
        ...,
        description="Hex-encoded SHA-256 digest of original raw input before modification.",
    )
    raw_length: int = Field(
        ...,
        ge=0,
        description="Character count of raw input prior to filtering and truncation.",
    )
    has_shell_metacharacters: bool = Field(
        ...,
        description="Whether raw input contained shell metacharacters (&, |, ;, $, etc.).",
    )
    has_sensitive_paths: bool = Field(
        ...,
        description="Whether raw input referenced sensitive host filesystem or socket paths.",
    )
    has_delimiter_breakout: bool = Field(
        ...,
        description="Whether raw input attempted to inject or close <untrusted_args> delimiters.",
    )
    has_prompt_injection_indicators: bool = Field(
        ...,
        description="Whether raw input matched adversarial prompt injection phrases.",
    )


def sanitize_untrusted_input(raw_input: str | None) -> SanitizedInput:
    """Sanitize untrusted input strings with defense-in-depth controls.

    1. Extracts deterministic security facts from raw string BEFORE truncation.
    2. Performs Unicode NFKC normalization.
    3. Strips control characters, bidi overrides, and zero-width spaces.
    4. Escapes XML-like delimiters (<, >) to prevent state template breakout.
    5. Truncates final output strictly to MAX_SANITIZED_LENGTH (128 characters).
    """
    # 1. Deterministic feature extraction on raw input prior to any alteration
    raw_text = "" if raw_input is None else str(raw_input)
    raw_length = len(raw_text)
    raw_sha256 = hashlib.sha256(raw_text.encode("utf-8")).hexdigest()
    raw_lower = raw_text.lower()

    has_shell_meta = any(char in SHELL_METACHARACTERS for char in raw_text)
    has_sens_paths = any(path in raw_lower for path in SENSITIVE_PATTERNS)
    has_breakout = "<untrusted_args>" in raw_lower or "</untrusted_args>" in raw_lower
    has_injection = any(keyword in raw_lower for keyword in PROMPT_INJECTION_KEYWORDS)

    # 2. Unicode NFKC normalization
    normalized = unicodedata.normalize("NFKC", raw_text)

    # 3. Filter control characters, bidi, and zero-width codes
    cleaned_chars: list[str] = []
    for char in normalized:
        cp = ord(char)
        if cp in DISALLOWED_CODEPOINTS:
            continue
        cat = unicodedata.category(char)
        # Strip categories: Control (Cc), Format (Cf), Surrogate (Cs),
        # Private-use (Co), Unassigned (Cn)
        if cat in {"Cc", "Cf", "Cs", "Co", "Cn"}:
            # Replace inline newline/tab with space if not at end of whitespace
            if char in {"\n", "\r", "\t"}:
                cleaned_chars.append(" ")
            continue
        cleaned_chars.append(char)

    filtered_text = "".join(cleaned_chars)

    # 4. Delimiter escaping to prevent breakout from <untrusted_args>...</untrusted_args>
    # Replace '<' and '>' with HTML-safe entity escapes
    escaped_text = filtered_text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

    # Collapse repeated whitespace
    normalized_spaces = " ".join(escaped_text.split())

    # 5. Strict truncation to MAX_SANITIZED_LENGTH (128 characters)
    sanitized_text = normalized_spaces[:MAX_SANITIZED_LENGTH]

    return SanitizedInput(
        sanitized_text=sanitized_text,
        raw_sha256=raw_sha256,
        raw_length=raw_length,
        has_shell_metacharacters=has_shell_meta,
        has_sensitive_paths=has_sens_paths,
        has_delimiter_breakout=has_breakout,
        has_prompt_injection_indicators=has_injection,
    )
