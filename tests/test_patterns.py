"""TOKEN_PATTERNS regex-floor suite (ROADMAP testing backlog item 1).

Every positive token is CONSTRUCTED at runtime — no literal secret shapes
in source (they'd trip secret scanners, including this proxy itself).
"""

from __future__ import annotations

import pytest

from redact_proxy.redactor import Redactor, _placeholder

# name -> synthetic token matching that pattern's grammar
POSITIVE = {
    "openai_anthropic": "sk-" + "a" * 24,
    "huggingface": "hf_" + "A" * 34,
    "aws_access_key": "AKIA" + "A" * 16,
    "aws_bedrock": "ABSK" + "A" * 100,
    "gcp_api_key": "AIza" + "a" * 35,
    "azure_ad_secret": "abc" + "8Q~" + "a" * 31,
    "digitalocean": "dop_v1_" + "a" * 64,
    "flyio": "fo1_" + "a" * 43,
    "heroku": "HRKU-AA" + "a" * 58,
    "github_classic": "ghp_" + "A" * 36,
    "github_fine_grained": "github_pat_" + "a" * 82,
    "gitlab": "glpat-" + "a" * 20,
    "slack_token": "xoxb-" + "a" * 12,
    "slack_app": "xapp-1-" + "ABC123" + "-45-" + "abc1",
    "slack_webhook": "hooks.slack.com/services/" + "T" * 44,
    "stripe": "sk_live_" + "a" * 24,
    "sendgrid": "SG." + "a" * 66,
    "twilio": "SK" + "a" * 32,
    "notion": "ntn_" + "1" * 11 + "a" * 35,
    "linear": "lin_api_" + "a" * 40,
    "postman": "PMAK-" + "a" * 24 + "-" + "a" * 34,
    "shopify": "shpat_" + "a" * 32,
    "npm": "npm_" + "a" * 36,
    "pypi": "pypi-AgEIcHlwaS5vcmc" + "a" * 50,
    "vault": "hvs." + "a" * 24,
    "terraform_cloud": "a" * 14 + ".atlasv1." + "a" * 60,
    "databricks": "dapi" + "a" * 32,
    "doppler": "dp.pt." + "a" * 43,
    "grafana_cloud": "glc_" + "a" * 32,
    "grafana_sa": "glsa_" + "a" * 32 + "_" + "a" * 8,
    "planetscale": "pscale_tkn_" + "a" * 32,
    "age": "AGE-SECRET-KEY-1" + "Q" * 58,
    "jwt": "ey" + "a" * 17 + "." + "ey" + "a" * 17 + "." + "a" * 10,
    "pem": "-----BEGIN PRIVATE KEY-----\n" + "A" * 64 + "\n-----END PRIVATE KEY-----",
    "url_credentials": "https://user:hunter2@example.com/path",
}

# Ordinary text/code that must produce ZERO redactions.
NEGATIVE = [
    "d4735e3a265e16eee03f59718b9b5d03019c07d8b6c51f90da3a666eec13ab35",  # git-ish sha
    "123e4567-e89b-12d3-a456-426614174000",  # uuid
    "https://example.com/path?q=1",  # url, no creds
    "user@example.com",
    "def redact(self, text: str) -> str:",
    'version = "0.1.0"; requires-python = ">=3.10"',
    "the eyes of the beholder went eyeing eyewear",  # ey... prose
    "AKIABCDEF",  # too-short prefix lookalike
    _placeholder("secret", "some-value"),  # our own placeholder: never re-matched
]


@pytest.fixture(scope="module")
def floor() -> Redactor:
    return Redactor()


@pytest.mark.parametrize("name", sorted(POSITIVE))
def test_positive(floor: Redactor, name: str) -> None:
    token = POSITIVE[name]
    out = floor.regex_redact(f"context before {token} context after")
    assert token not in out, f"{name}: token survived the regex floor"
    assert "REDACTED:secret:" in out, f"{name}: no placeholder emitted"


@pytest.mark.parametrize("text", NEGATIVE)
def test_negative(floor: Redactor, text: str) -> None:
    assert floor.regex_redact(text) == text
