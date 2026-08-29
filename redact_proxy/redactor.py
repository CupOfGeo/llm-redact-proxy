"""Two-layer PII redaction: regex floor + MLX OPF model.

Layer 1 (regex): known secret-token formats (API keys, JWTs, private key
blocks). Guaranteed catch, runs on everything, microseconds.

Layer 2 (OPF): the MLX 8-bit OpenAI Privacy Filter finds fuzzy PII the
regexes can't (freeform account numbers, passwords in prose). Only spans
whose category is in `categories` are redacted.

Placeholders are deterministic (keyed by a short hash of the secret) so
the same secret always redacts to the same placeholder — this keeps
Anthropic prompt caching intact and lets the model refer to "that same
token" across turns without ever seeing it.
"""

from __future__ import annotations

import hashlib
import re
from typing import Any

DEFAULT_MODEL = "OpenMed/privacy-filter-mlx-8bit"

# Vital-PII default: credentials and account numbers. Person/email/etc. are
# deliberately off — redacting them cripples ordinary coding work.
DEFAULT_CATEGORIES = frozenset({"secret", "account_number"})

# Known token formats — the guaranteed floor. OPF backstops what these miss.
# Curated from gitleaks' default ruleset (github.com/gitleaks/gitleaks):
# self-identifying prefixed formats only. Context-keyword rules ("cloudflare"
# near 40 hex chars) are deliberately excluded — too false-positive-prone;
# fuzzy detection is OPF's job.
TOKEN_PATTERNS = [
    # AI / ML providers
    re.compile(r"sk-[A-Za-z0-9_-]{16,}"),  # OpenAI/Anthropic (sk-ant-*, sk-proj-*, ...)
    re.compile(r"\b(?:hf_|api_org_)[A-Za-z]{34}\b"),  # HuggingFace
    # Cloud
    re.compile(r"\b(?:A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA)[A-Z2-7]{16}\b"),  # AWS
    re.compile(r"\bABSK[A-Za-z0-9+/]{100,}={0,2}"),  # AWS Bedrock long-lived
    re.compile(r"\bAIza[\w-]{35}\b"),  # GCP API key
    re.compile(r"[A-Za-z0-9_~.]{3}\dQ~[A-Za-z0-9_~.-]{31,34}"),  # Azure AD secret
    re.compile(r"\bd(?:op|oo|or)_v1_[a-f0-9]{64}\b"),  # DigitalOcean
    re.compile(r"\b(?:fo1_[\w-]{43}|fm[12][ar]?_[A-Za-z0-9+/]{100,}={0,3})"),  # Fly.io
    re.compile(r"\bHRKU-AA[0-9a-zA-Z_-]{58}\b"),  # Heroku v2
    # Git forges / CI
    re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}\b"),  # GitHub classic
    re.compile(r"\bgithub_pat_\w{82}\b"),  # GitHub fine-grained
    re.compile(  # GitLab token family (PATs, runner, deploy, OAuth, agent, ...)
        r"\bgl(?:pat|ptt|rt|dt|ft|oas|soat|imt|agent|cbt|ffct)-[\w-]{20,}"
    ),
    # Chat / SaaS
    re.compile(r"xox[abeoprs]-[A-Za-z0-9-]{10,}"),  # Slack tokens
    re.compile(r"\bxapp-\d-[A-Z0-9]+-\d+-[a-z0-9]+"),  # Slack app token
    re.compile(  # Slack webhook URL
        r"hooks\.slack\.com/(?:services|workflows|triggers)/[A-Za-z0-9+/]{43,56}"
    ),
    re.compile(r"\b(?:sk|rk)_(?:test|live|prod)_[a-zA-Z0-9]{10,99}\b"),  # Stripe
    re.compile(r"\bSG\.[A-Za-z0-9=_.-]{66}"),  # SendGrid
    re.compile(r"\bSK[0-9a-fA-F]{32}\b"),  # Twilio API key
    re.compile(r"\bntn_[0-9]{11}[A-Za-z0-9]{35}\b"),  # Notion
    re.compile(r"\blin_api_[A-Za-z0-9]{40}\b"),  # Linear
    re.compile(r"\bPMAK-[a-f0-9]{24}-[a-f0-9]{34}\b"),  # Postman
    re.compile(r"\bshp(?:at|ca|pa|ss)_[a-fA-F0-9]{32}\b"),  # Shopify
    # Package registries
    re.compile(r"\bnpm_[A-Za-z0-9]{36}\b"),  # npm
    re.compile(r"\bpypi-AgEIcHlwaS5vcmc[\w-]{50,}"),  # PyPI upload token
    # Infra / secrets managers
    re.compile(r"\bhv[sb]\.[\w-]{24,}"),  # HashiCorp Vault
    re.compile(r"[a-z0-9]{14}\.atlasv1\.[A-Za-z0-9_=-]{60,70}"),  # Terraform Cloud
    re.compile(r"\bdapi[a-f0-9]{32}(?:-\d)?\b"),  # Databricks
    re.compile(r"\bdp\.pt\.[A-Za-z0-9]{43}"),  # Doppler
    re.compile(r"\bglc_[A-Za-z0-9+/]{32,400}={0,3}"),  # Grafana Cloud
    re.compile(r"\bglsa_[A-Za-z0-9]{32}_[A-Fa-f0-9]{8}\b"),  # Grafana svc account
    re.compile(r"\bpscale_(?:tkn|oauth|pw)_[\w=.-]{32,64}"),  # PlanetScale
    re.compile(r"\bAGE-SECRET-KEY-1[QPZRY9X8GF2TVDW0S3JN54KHCE6MUA7L]{58}\b"),  # age
    # Generic formats
    re.compile(  # JWT
        r"\bey[A-Za-z0-9]{17,}\.ey[A-Za-z0-9_/-]{17,}\.[A-Za-z0-9_/-]{10,}={0,2}"
    ),
    # PEM private key blocks (incl. OPENSSH, PGP). This is the only
    # multi-line pattern, and it runs over the raw JSON body: the span
    # must never cross a bare `"` (a JSON string boundary) or an unmatched
    # BEGIN swallows every message up to the next END — tool_use blocks
    # included, still as valid JSON. Escapes (\" \\n) are allowed; the
    # length cap bounds the damage (a 16 KB key does not exist).
    re.compile(
        r"-----BEGIN[ A-Z0-9_-]{0,100}PRIVATE KEY(?: BLOCK)?-----"
        r'(?:[^"\\]|\\[\s\S]){64,16000}?'
        r"-----END[ A-Z0-9_-]{0,100}PRIVATE KEY(?: BLOCK)?-----"
    ),
    re.compile(  # credentials embedded in URLs: scheme://user:password@host
        r"\b[a-zA-Z][a-zA-Z0-9+.-]{1,20}://[^/\s:@'\"]{1,64}:[^/\s@'\"]{1,128}@"
    ),
]

# Hard cap on the text handed to one OPF inference call. Cost grows
# superlinearly with length (measured on M-series: 16 KB ≈ 4.6 s, 32 KB ≈
# 22 s in one call; 4–8 KB pieces are the most efficient per byte).
CHUNK_CHARS = 6000

_CACHE_MAX = 8192

# The full placeholder grammar. Unambiguous: nothing else in ordinary
# text or code produces this shape (see tests/test_patterns.py).
PLACEHOLDER_RE = re.compile(r"⟨REDACTED:[a-z0-9_]+:[0-9a-f]{6}⟩")
_REVERSE_MAX = 4096


def _placeholder(category: str, value: str) -> str:
    digest = hashlib.sha256(value.encode()).hexdigest()[:6]
    return f"⟨REDACTED:{category}:{digest}⟩"


def _normalize_label(label: str) -> str:
    return label.lower().removeprefix("private_")


_WS = re.compile(r"\s")


def _hard_split(piece: str) -> list[str]:
    """Cut a piece longer than CHUNK_CHARS, after the last whitespace in the
    back half of each window when there is one (never mid-token if
    avoidable), else at the cap. A freeform secret straddling a cut can be
    missed by OPF — accepted; the regex floor saw the whole text already."""
    out: list[str] = []
    while len(piece) > CHUNK_CHARS:
        cut = CHUNK_CHARS
        for m in _WS.finditer(piece, CHUNK_CHARS // 2, CHUNK_CHARS):
            cut = m.end()
        out.append(piece[:cut])
        piece = piece[cut:]
    out.append(piece)
    return out


def _chunks(text: str) -> list[str]:
    """Pieces of at most CHUNK_CHARS, packed on line boundaries.

    Whole lines are packed while they fit; any piece still over the cap
    (a single enormous line: minified JSON, base64, a tool result with no
    newlines) is hard-split so no inference call ever exceeds it.
    """
    if len(text) <= CHUNK_CHARS:
        return [text]
    pieces: list[str] = []
    buf: list[str] = []
    size = 0
    for line in text.splitlines(keepends=True):
        if size + len(line) > CHUNK_CHARS and buf:
            pieces.append("".join(buf))
            buf, size = [], 0
        buf.append(line)
        size += len(line)
    if buf:
        pieces.append("".join(buf))
    return [part for piece in pieces for part in _hard_split(piece)]


class Redactor:
    """Regex + OPF redaction with a per-text result cache."""

    def __init__(
        self,
        model_id: str = DEFAULT_MODEL,
        categories: frozenset[str] = DEFAULT_CATEGORIES,
    ) -> None:
        self.model_id = model_id
        self.categories = categories
        self._pipe: Any = None
        # sha256(text) -> redacted text. Conversation history repeats
        # verbatim every request, so this makes scanning incremental.
        self._cache: dict[str, str] = {}
        # placeholder -> original value, for the response path (restore()).
        # Memory only, never disk. Clear rule: only ever together with
        # _cache — a cache hit returns early without re-recording, so
        # clearing reverse alone strands placeholders in cached history.
        self.reverse: dict[str, str] = {}
        # Cumulative counters; the server snapshots these per request.
        self.stats = {"cached": 0, "scanned": 0, "redactions": 0}
        # Set by the server while the model loads in the background;
        # requests are refused (503) until it clears. load_error keeps
        # the failure reason for /health.
        self.loading = False
        self.load_error: str | None = None

    def load(self) -> None:
        from huggingface_hub import snapshot_download
        from openmed.mlx.inference import create_mlx_pipeline

        model_path = snapshot_download(self.model_id)
        self._pipe = create_mlx_pipeline(model_path)

    def _record(self, category: str, value: str) -> str:
        """Placeholder for `value`, remembering the reverse mapping."""
        placeholder = _placeholder(category, value)
        self.reverse[placeholder] = value
        self.stats["redactions"] += 1
        return placeholder

    def restore(self, text: str) -> str:
        """Replace known placeholders with their original values.

        Unknown placeholders (e.g. minted before a restart) pass through
        unchanged — memory-only by design.
        """
        return PLACEHOLDER_RE.sub(
            lambda m: self.reverse.get(m.group(), m.group()), text
        )

    def regex_redact(self, text: str) -> str:
        """Layer 1 only. Safe to run on raw request bytes."""

        def replace(m: re.Match) -> str:
            return self._record("secret", m.group())

        for pattern in TOKEN_PATTERNS:
            text = pattern.sub(replace, text)
        return text

    def _opf_spans(self, text: str) -> list[dict]:
        spans: list[dict] = []
        offset = 0
        for chunk in _chunks(text):
            raw = self._pipe(chunk)
            items = raw if isinstance(raw, list) else []
            for s in items:
                if not isinstance(s, dict):
                    continue
                label = s.get("entity_group") or s.get("label") or s.get("entity")
                start, end = s.get("start"), s.get("end")
                if label is None or start is None or end is None:
                    continue
                spans.append(
                    {
                        "category": _normalize_label(str(label)),
                        "start": int(start) + offset,
                        "end": int(end) + offset,
                    }
                )
            offset += len(chunk)
        return spans

    def redact(self, text: str) -> str:
        """Both layers, cached. Returns text with vital PII replaced."""
        if not text:
            return text
        if len(self.reverse) >= _REVERSE_MAX:
            self.reverse.clear()
            self._cache.clear()
        key = hashlib.sha256(text.encode()).hexdigest()
        cached = self._cache.get(key)
        if cached is not None:
            self.stats["cached"] += 1
            return cached
        self.stats["scanned"] += 1

        out = self.regex_redact(text)
        if self._pipe is not None:
            spans = [
                s for s in self._opf_spans(out) if s["category"] in self.categories
            ]
            # Replace back-to-front so earlier offsets stay valid; skip overlaps.
            spans.sort(key=lambda s: s["start"], reverse=True)
            ph_spans = [m.span() for m in PLACEHOLDER_RE.finditer(out)]
            prev_start = len(out) + 1
            for s in spans:
                if s["end"] > prev_start:
                    continue
                value = out[s["start"] : s["end"]]
                # Never touch an existing placeholder (regex layer ran
                # first) — including OPF spans strictly *inside* one.
                if any(s["start"] < pe and s["end"] > ps for ps, pe in ph_spans):
                    continue
                out = (
                    out[: s["start"]]
                    + self._record(s["category"], value)
                    + out[s["end"] :]
                )
                prev_start = s["start"]

        if len(self._cache) >= _CACHE_MAX:
            self._cache.clear()
        self._cache[key] = out
        return out
