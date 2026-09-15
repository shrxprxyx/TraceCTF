"""
Evidence linker for TraceCTF.

Persists a finding dict (as produced by finding_extractor.py) into the
database, creating both the Finding row and the FindingEvidence link
rows that tie it back to the specific Event IDs that support it.

This is the concrete implementation of "every finding must reference
its supporting evidence" (FR-AI-4) — a finding can never exist in the
DB without at least one evidence link.
"""

from __future__ import annotations

from typing import Optional

from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import Finding, FindingEvidence

PIPELINE_VERSION = "v1"


async def persist_finding(
    db: AsyncSession,
    session_id: int,
    finding_dict: dict,
) -> Optional[Finding]:
    """
    Writes a finding + its evidence links in a single transaction.
    Returns the persisted Finding, or None if the finding_dict has no
    evidence (which should never happen if finding_extractor.py is
    working correctly — this is a defensive guard, not expected path).
    """
    evidence_ids = finding_dict.get("evidence_event_ids", [])
    if not evidence_ids:
        # Refuse to create an unlinked finding — evidence grounding is
        # a hard invariant of this system, not a best-effort guideline.
        return None

    finding = Finding(
        session_id=session_id,
        name=finding_dict["name"],
        finding_type=finding_dict.get("finding_type", "other"),
        confidence_score=finding_dict.get("confidence_score"),
        confidence_label=finding_dict.get("confidence_label"),
        is_successful_path=finding_dict.get("is_successful_path", False),
        pipeline_version=PIPELINE_VERSION,
    )
    db.add(finding)
    await db.flush()  # assigns finding.id without committing yet

    for event_id in evidence_ids:
        db.add(FindingEvidence(finding_id=finding.id, event_id=event_id))

    await db.commit()
    await db.refresh(finding)
    return finding


async def get_findings_with_evidence(
    db: AsyncSession,
    session_id: int,
) -> list[dict]:
    """
    Convenience read helper: fetches all findings for a session along
    with their linked evidence event IDs, in a single shape useful for
    API responses and the graph builder.
    """
    from sqlalchemy import select
    from app.db.models import Session as SessionModel  # avoid name clash

    result = await db.execute(
        select(Finding).where(Finding.session_id == session_id)
    )
    findings = result.scalars().all()

    output = []
    for f in findings:
        await db.refresh(f, attribute_names=["evidence_links"])
        output.append({
            "id": f.id,
            "name": f.name,
            "finding_type": f.finding_type,
            "confidence_score": f.confidence_score,
            "confidence_label": f.confidence_label,
            "is_successful_path": f.is_successful_path,
            "evidence_event_ids": [link.event_id for link in f.evidence_links],
        })
    return output