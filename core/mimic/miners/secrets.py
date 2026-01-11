from __future__ import annotations

import math
import re
from typing import Dict, List, Tuple

from core.mimic.models import Secret


# Known-ish token patterns (defensive scanning; ALWAYS redact)
_AWS_ACCESS_KEY_RE = re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b")
_GITHUB_TOKEN_RE = re.compile(r"\b(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{30,200}\b")
_SLACK_TOKEN_RE = re.compile(r"\b(xox[baprs]-[A-Za-z0-9-]{10,200})\b")
_STRIPE_LIVE_RE = re.compile(r"\b(sk_live_[A-Za-z0-9]{10,200})\b")
_PRIVATE_KEY_PEM_RE = re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")

# Generic high-entropy candidates
_BASE64ISH_RE = re.compile(r"\b[A-Za-z0-9+/=_-]{24,256}\b")


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    ent = 0.0
    n = len(s)
    for c in freq.values():
        p = c / n
        ent -= p * math.log2(p)
    return ent


def redact(s: str, keep: int = 4) -> str:
    if len(s) <= keep * 2:
        return "*" * len(s)
    return f"{s[:keep]}...{s[-keep:]}"


def _mk_evidence(text: str, start: int, end: int) -> Dict:
    return {
        "start": start,
        "end": end,
        "context": text[max(0, start - 30): min(len(text), end + 30)],
    }


def mine_secrets(asset_id: str, text: str) -> List[Secret]:
    secrets: List[Secret] = []
    seen = set()

    def add(secret_type: str, value: str, confidence: int, start: int, end: int) -> None:
        key = (secret_type, value)
        if key in seen:
            return
        seen.add(key)
        secrets.append(
            Secret(
                secret_type=secret_type,
                confidence=confidence,
                redacted_preview=redact(value),
                evidence=_mk_evidence(text, start, end),
            )
        )

    for m in _PRIVATE_KEY_PEM_RE.finditer(text):
        add("private_key_pem_header", m.group(0), 95, m.start(), m.end())

    for m in _AWS_ACCESS_KEY_RE.finditer(text):
        add("aws_access_key_id", m.group(0), 90, m.start(), m.end())

    for m in _GITHUB_TOKEN_RE.finditer(text):
        add("github_token", m.group(0), 90, m.start(), m.end())

    for m in _SLACK_TOKEN_RE.finditer(text):
        add("slack_token", m.group(0), 85, m.start(), m.end())

    for m in _STRIPE_LIVE_RE.finditer(text):
        add("stripe_live_secret", m.group(0), 92, m.start(), m.end())

    # High-entropy sweep (careful: many false positives)
    for m in _BASE64ISH_RE.finditer(text):
        cand = m.group(0)
        # Skip obviously non-secret-ish tokens
        if cand.lower().startswith("http") or cand.lower().startswith("webpack"):
            continue
        ent = shannon_entropy(cand)
        # entropy threshold tuned to reduce noise
        if ent >= 4.2 and len(cand) >= 28:
            add("high_entropy_string", cand, 40, m.start(), m.end())

    return secrets
