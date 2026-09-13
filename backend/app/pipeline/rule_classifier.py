"""
Rule-based fallback classifier for TraceCTF.

Used when the LLM (Ollama) is unavailable, times out, or returns
unparseable output. Recognizes well-known security tool invocations by
pattern-matching the command text, and produces a finding dict in the
same shape the LLM-based finding_extractor would — so downstream code
(graph_builder, writeup_generator) doesn't need to know which path
produced a given finding.

This is intentionally conservative: it only classifies commands it
recognizes with high confidence. Anything unrecognized is classified as
"recon" / LOW confidence rather than guessed at — false precision here
would be worse than admitting uncertainty.
"""

from __future__ import annotations

import re
from typing import Optional, TypedDict


class RuleFinding(TypedDict):
    name: str
    finding_type: str
    confidence_score: float
    confidence_label: str


# ---------------------------------------------------------------------------
# Tool signature table: (regex pattern, finding name, finding_type, confidence)
# Ordered roughly by specificity — more specific patterns first, since the
# first match wins.
# ---------------------------------------------------------------------------
_TOOL_SIGNATURES: list[tuple[re.Pattern, str, str, float]] = [
    (re.compile(r"^\s*nmap\b", re.IGNORECASE), "Port/Service Scan (nmap)", "recon", 0.9),
    (re.compile(r"^\s*(gobuster|dirb|dirbuster|feroxbuster)\b", re.IGNORECASE),
     "Directory/Content Enumeration", "recon", 0.9),
    (re.compile(r"^\s*sqlmap\b", re.IGNORECASE), "SQL Injection Attempt (sqlmap)", "vulnerability", 0.85),
    (re.compile(r"^\s*hydra\b", re.IGNORECASE), "Credential Brute-Force Attempt (hydra)", "credential", 0.8),
    (re.compile(r"^\s*(john|hashcat)\b", re.IGNORECASE), "Password/Hash Cracking Attempt", "credential", 0.8),
    (re.compile(r"^\s*nc\s|^\s*ncat\s|^\s*netcat\b", re.IGNORECASE), "Netcat Connection/Listener", "access", 0.7),
    (re.compile(r"^\s*ssh\s+\S+@", re.IGNORECASE), "SSH Access Attempt", "access", 0.75),
    (re.compile(r"^\s*sudo\s+-l\b", re.IGNORECASE), "Sudo Privilege Enumeration", "privilege_escalation", 0.85),
    (re.compile(r"find\s+/\s+-perm\s+-4000", re.IGNORECASE), "SUID Binary Enumeration", "privilege_escalation", 0.85),
    (re.compile(r"^\s*curl\s|^\s*wget\s", re.IGNORECASE), "HTTP Request (curl/wget)", "recon", 0.6),
    (re.compile(r"^\s*python[3]?\s+.*exploit", re.IGNORECASE), "Custom Exploit Script Execution", "vulnerability", 0.7),
    (re.compile(r"^\s*msfconsole\b|^\s*msfvenom\b", re.IGNORECASE), "Metasploit Framework Usage", "vulnerability", 0.75),
]

# Output patterns that suggest success/failure, used to adjust confidence
_SUCCESS_INDICATORS = re.compile(
    r"(open\s+ssh|open\s+http|welcome|successfully|shell\s+opened|root@|# $|uid=0)",
    re.IGNORECASE,
)
_FAILURE_INDICATORS = re.compile(
    r"(connection refused|failed|denied|not found|timeout|no route to host|404 not found)",
    re.IGNORECASE,
)


def classify_command(command: Optional[str], stdout: Optional[str] = None) -> RuleFinding:
    """
    Classifies a single terminal command using known tool signatures.
    Falls back to a generic LOW-confidence "recon" finding if nothing matches.
    """
    if not command:
        return RuleFinding(
            name="Unclassified Activity",
            finding_type="other",
            confidence_score=0.2,
            confidence_label="LOW",
        )

    for pattern, name, finding_type, base_confidence in _TOOL_SIGNATURES:
        if pattern.search(command):
            score = base_confidence
            label = _score_to_label(score)

            # Nudge confidence based on output, if available
            if stdout:
                if _SUCCESS_INDICATORS.search(stdout):
                    score = min(score + 0.05, 0.95)
                elif _FAILURE_INDICATORS.search(stdout):
                    score = max(score - 0.25, 0.1)
                    finding_type = "dead_end" if score < 0.4 else finding_type

            return RuleFinding(
                name=name,
                finding_type=finding_type,
                confidence_score=round(score, 2),
                confidence_label=_score_to_label(score),
            )

    # No known signature matched
    return RuleFinding(
        name="Unrecognized Command",
        finding_type="other",
        confidence_score=0.25,
        confidence_label="LOW",
    )


def _score_to_label(score: float) -> str:
    if score >= 0.75:
        return "HIGH"
    elif score >= 0.45:
        return "MEDIUM"
    else:
        return "LOW"