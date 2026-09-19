"""
Write-up generator for TraceCTF.

Takes all findings for a session (with their linked evidence) and
produces a Markdown write-up via the LLM. Every claim the LLM makes
must be tagged with the event ID(s) it's based on, using an inline
marker format: [[evidence:12,13]] — this is parsed out by the
verification engine (next file) to check claims against real evidence
before the write-up is considered final.

If the LLM is unavailable, falls back to a template-based write-up
built directly from findings/evidence — less narrative, but still
100% evidence-accurate, since it's not generated prose at all.
"""

from __future__ import annotations

from typing import Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import WriteupVersion, Finding, Event
from app.pipeline.evidence_linker import get_findings_with_evidence
from app.pipeline.llm_client import OllamaClient

_SYSTEM_PROMPT = """You are a security analyst writing a CTF (Capture The Flag) technical write-up based ONLY on the findings and evidence provided. Do not invent steps, tools, or outcomes not present in the data given to you.

For EVERY factual claim you make (a vulnerability found, a command run, an outcome achieved), you MUST tag it with the evidence event ID(s) it's based on, using this exact inline format immediately after the sentence: [[evidence:ID1,ID2]]

Example:
"The target's login endpoint was found to be vulnerable to SQL injection. [[evidence:14,15]]"

If you are not given evidence for a claim, do not make that claim.

Write in clear, professional technical prose, organized with Markdown headers (## Reconnaissance, ## Exploitation, ## Privilege Escalation, etc. — only include sections that have findings). Do not use markdown code fences around the whole response — respond with plain Markdown text directly.
"""


def _format_findings_for_prompt(findings: list[dict]) -> str:
    lines = []
    for f in findings:
        lines.append(
            f"Finding: {f['name']}\n"
            f"Type: {f['finding_type']}\n"
            f"Confidence: {f['confidence_label']}\n"
            f"Successful path: {f['is_successful_path']}\n"
            f"Evidence event IDs: {f['evidence_event_ids']}\n"
        )
    return "\n---\n".join(lines)


def _template_fallback_writeup(findings: list[dict]) -> str:
    """
    Used when the LLM is unavailable. Produces a plain, structured
    write-up directly from finding data — no prose generation, so it
    carries zero hallucination risk by construction.
    """
    if not findings:
        return "# CTF Write-up\n\n_No findings recorded yet for this session._\n"

    lines = ["# CTF Write-up\n"]
    successful = [f for f in findings if f["is_successful_path"]]
    dead_ends = [f for f in findings if not f["is_successful_path"]]

    if successful:
        lines.append("## Successful Path\n")
        for f in successful:
            lines.append(
                f"- **{f['name']}** ({f['finding_type']}, confidence: {f['confidence_label']}) "
                f"[[evidence:{','.join(map(str, f['evidence_event_ids']))}]]"
            )

    if dead_ends:
        lines.append("\n## Alternative Attempts / Dead Ends\n")
        for f in dead_ends:
            lines.append(
                f"- {f['name']} ({f['finding_type']}, confidence: {f['confidence_label']}) "
                f"[[evidence:{','.join(map(str, f['evidence_event_ids']))}]]"
            )

    return "\n".join(lines)


async def generate_writeup(
    db: AsyncSession,
    session_id: int,
    llm_client: Optional[OllamaClient] = None,
) -> tuple[str, str]:
    """
    Returns (markdown_content, generation_source) where generation_source
    is "llm" or "template" — surfaced to the frontend so the user knows
    whether they're looking at AI prose or a raw structured fallback.
    """
    findings = await get_findings_with_evidence(db, session_id)

    if not findings:
        return "# CTF Write-up\n\n_No findings recorded yet for this session._\n", "template"

    client = llm_client or OllamaClient()
    llm_available = await client.is_available()

    if llm_available:
        prompt = _format_findings_for_prompt(findings)
        result = await client.generate_text(prompt=prompt, system=_SYSTEM_PROMPT)
        if result:
            return result, "llm"
        # LLM reachable but generation failed/empty — fall through to template

    return _template_fallback_writeup(findings), "template"


async def compute_completion_percentage(findings: list[dict]) -> float:
    """
    Heuristic completion score (FR-UI-5): based on whether the write-up
    covers a spread of expected attack-chain stages, not just a raw
    finding count (10 recon findings shouldn't look "more complete"
    than 1 recon + 1 exploit + 1 privesc).
    """
    expected_stages = {"recon", "vulnerability", "credential", "access", "privilege_escalation"}
    covered_stages = {f["finding_type"] for f in findings if f["finding_type"] in expected_stages}
    if not expected_stages:
        return 0.0
    return round(len(covered_stages) / len(expected_stages) * 100, 1)


async def persist_writeup_version(
    db: AsyncSession,
    session_id: int,
    content_markdown: str,
    completion_percentage: float,
) -> WriteupVersion:
    """
    Writes a new version row, auto-incrementing version_number per session.
    Never overwrites a prior version — this is what enables FR-WU-4
    (diffing between versions) later.
    """
    result = await db.execute(
        select(WriteupVersion.version_number)
        .where(WriteupVersion.session_id == session_id)
        .order_by(WriteupVersion.version_number.desc())
        .limit(1)
    )
    last_version = result.scalar_one_or_none() or 0

    version = WriteupVersion(
        session_id=session_id,
        version_number=last_version + 1,
        content_markdown=content_markdown,
        completion_percentage=completion_percentage,
    )
    db.add(version)
    await db.commit()
    await db.refresh(version)
    return version