"""
Finding extraction pipeline stage for TraceCTF.

Given one or more raw Event rows, produces Finding-shaped dicts with
evidence links back to the originating event IDs. Tries the local LLM
first (richer, can group multiple related events into one finding);
falls back to the deterministic rule_classifier per-event if the LLM
is unavailable or its response can't be trusted.

Output shape (per finding):
{
    "name": str,
    "finding_type": str,
    "confidence_score": float,
    "confidence_label": "HIGH"|"MEDIUM"|"LOW",
    "is_successful_path": bool,
    "evidence_event_ids": list[int],
    "source": "llm" | "rule_based",
}
"""

from __future__ import annotations

from typing import Optional

from app.db.models import Event
from app.pipeline.llm_client import OllamaClient
from app.pipeline.rule_classifier import classify_command
from app.config import settings

_SYSTEM_PROMPT = """You are a security analyst assistant helping reconstruct a CTF (Capture The Flag) attack path from recorded terminal activity.

You will be given one or more terminal events (command + output). Determine if they represent a meaningful security finding (e.g., a vulnerability discovery, credential access, privilege escalation, reconnaissance result, or a failed/dead-end attempt).

Respond ONLY with a JSON object in this exact shape, no extra text:
{
  "is_finding": true|false,
  "name": "short finding name",
  "finding_type": "vulnerability|credential|access|privilege_escalation|recon|dead_end|other",
  "confidence_score": 0.0-1.0,
  "is_successful_path": true|false,
  "reasoning": "one sentence explaining why, based only on what the output shows"
}

Rules:
- Only claim "is_finding": true if the output actually shows evidence of it. Do not invent outcomes not shown in the output.
- If the command failed or was denied, set is_successful_path to false and consider finding_type "dead_end".
- confidence_score should reflect how directly the output supports the finding — 0.9+ only if the output is unambiguous.
"""


def _format_events_for_prompt(events: list[Event]) -> str:
    lines = []
    for e in events:
        lines.append(
            f"[event_id={e.id}] command: {e.command!r}\n"
            f"cwd: {e.cwd}\n"
            f"stdout: {(e.stdout or '')[:1000]}\n"
            f"stderr: {(e.stderr or '')[:500]}\n"
        )
    return "\n---\n".join(lines)


def _score_to_label(score: float) -> str:
    if score >= 0.75:
        return "HIGH"
    elif score >= 0.45:
        return "MEDIUM"
    else:
        return "LOW"


async def extract_finding_from_events(
    events: list[Event],
    llm_client: Optional[OllamaClient] = None,
) -> Optional[dict]:
    """
    Attempts LLM-based extraction for a group of related terminal events.
    Falls back to rule-based classification of the primary (first) event
    if the LLM is unavailable or its output is untrustworthy.
    """
    if not events:
        return None

    terminal_events = [e for e in events if e.source == "terminal" and e.command]
    if not terminal_events:
        return None  # non-terminal events (screenshots, fs changes) aren't classified here

    client = llm_client or OllamaClient()

    if settings.use_rule_based_fallback:
        llm_available = await client.is_available()
    else:
        llm_available = True  # force LLM path if fallback disabled (not recommended)

    if llm_available:
        prompt = _format_events_for_prompt(terminal_events)
        result = await client.generate_json(prompt=prompt, system=_SYSTEM_PROMPT)

        if result and _is_valid_llm_result(result):
            if not result.get("is_finding"):
                return None
            score = float(result.get("confidence_score", 0.5))
            return {
                "name": result.get("name", "Unnamed Finding"),
                "finding_type": result.get("finding_type", "other"),
                "confidence_score": round(min(max(score, 0.0), 1.0), 2),
                "confidence_label": _score_to_label(score),
                "is_successful_path": bool(result.get("is_successful_path", False)),
                "evidence_event_ids": [e.id for e in terminal_events],
                "source": "llm",
            }
       
    # ---- Rule-based fallback path ----
    primary_event = terminal_events[0]
    rule_result = classify_command(primary_event.command, primary_event.stdout)
    return {
        "name": rule_result["name"],
        "finding_type": rule_result["finding_type"],
        "confidence_score": rule_result["confidence_score"],
        "confidence_label": rule_result["confidence_label"],
        "is_successful_path": rule_result["finding_type"] not in ("dead_end", "other"),
        "evidence_event_ids": [primary_event.id],
        "source": "rule_based",
    }


def _is_valid_llm_result(result: dict) -> bool:
    """
    Defensive validation of the LLM's JSON output before trusting it.
    A local model can return a JSON object that's syntactically valid but
    semantically wrong (missing keys, wrong types) — this catches that
    before it reaches the database.
    """
    required_keys = {"is_finding", "confidence_score"}
    if not required_keys.issubset(result.keys()):
        return False
    try:
        score = float(result["confidence_score"])
        if not (0.0 <= score <= 1.0):
            return False
    except (TypeError, ValueError):
        return False
    return True