"""
Findings API for TraceCTF.

  - GET /sessions/{id}/findings        -> list findings with evidence
  - GET /findings/{finding_id}         -> single finding detail
  - GET /sessions/{id}/graph           -> attack graph (nodes + edges) as JSON,
                                           ready for frontend graph rendering

The graph endpoint separates the "successful path" from dead ends per
FR-GRAPH-2, so the frontend can render them visually distinctly without
needing its own classification logic.
"""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.database import get_db
from app.db.models import Finding, FindingEvidence, AttackRelationship
from app.pipeline.evidence_linker import get_findings_with_evidence

router = APIRouter(tags=["findings"])


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------
class FindingResponse(BaseModel):
    id: int
    name: str
    finding_type: str | None
    confidence_score: float | None
    confidence_label: str | None
    is_successful_path: bool
    evidence_event_ids: list[int]


class GraphNode(BaseModel):
    id: int
    name: str
    finding_type: str | None
    confidence_label: str | None
    is_successful_path: bool


class GraphEdge(BaseModel):
    from_id: int
    to_id: int
    relationship_type: str


class GraphResponse(BaseModel):
    nodes: list[GraphNode]
    edges: list[GraphEdge]


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------
@router.get("/sessions/{session_id}/findings", response_model=list[FindingResponse])
async def list_findings(session_id: int, db: AsyncSession = Depends(get_db)):
    findings = await get_findings_with_evidence(db, session_id)
    return findings


@router.get("/findings/{finding_id}", response_model=FindingResponse)
async def get_finding(finding_id: int, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Finding).where(Finding.id == finding_id))
    finding = result.scalar_one_or_none()
    if finding is None:
        raise HTTPException(404, f"Finding {finding_id} not found")

    await db.refresh(finding, attribute_names=["evidence_links"])
    return FindingResponse(
        id=finding.id,
        name=finding.name,
        finding_type=finding.finding_type,
        confidence_score=finding.confidence_score,
        confidence_label=finding.confidence_label,
        is_successful_path=finding.is_successful_path,
        evidence_event_ids=[link.event_id for link in finding.evidence_links],
    )


@router.get("/sessions/{session_id}/graph", response_model=GraphResponse)
async def get_attack_graph(session_id: int, db: AsyncSession = Depends(get_db)):
    findings_result = await db.execute(
        select(Finding).where(Finding.session_id == session_id)
    )
    findings = findings_result.scalars().all()

    edges_result = await db.execute(
        select(AttackRelationship).where(AttackRelationship.session_id == session_id)
    )
    relationships = edges_result.scalars().all()

    nodes = [
        GraphNode(
            id=f.id,
            name=f.name,
            finding_type=f.finding_type,
            confidence_label=f.confidence_label,
            is_successful_path=f.is_successful_path,
        )
        for f in findings
    ]
    edges = [
        GraphEdge(
            from_id=r.from_finding_id,
            to_id=r.to_finding_id,
            relationship_type=r.relationship_type,
        )
        for r in relationships
    ]

    return GraphResponse(nodes=nodes, edges=edges)