"""
SQLAlchemy models for TraceCTF.
Mirrors the schema defined in SRS Section 6.
Raw evidence (Event) is treated as immutable — never updated after insert,
only ever read or referenced by AI-derived tables (Finding, etc).
"""

from __future__ import annotations

import datetime
from typing import Optional

from sqlalchemy import (
    ForeignKey,
    JSON,
    CheckConstraint,
    UniqueConstraint,
)
from sqlalchemy.orm import (
    DeclarativeBase,
    Mapped,
    mapped_column,
    relationship,
)


class Base(DeclarativeBase):
    pass


# ---------------------------------------------------------------------------
# Sessions
# ---------------------------------------------------------------------------
class Session(Base):
    __tablename__ = "sessions"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(nullable=False)
    challenge_name: Mapped[Optional[str]] = mapped_column(nullable=True)
    started_at: Mapped[datetime.datetime] = mapped_column(nullable=False)
    ended_at: Mapped[Optional[datetime.datetime]] = mapped_column(nullable=True)
    status: Mapped[str] = mapped_column(default="active")

    __table_args__ = (
        CheckConstraint("status IN ('active','paused','completed')", name="ck_session_status"),
    )

    events: Mapped[list["Event"]] = relationship(back_populates="session", cascade="all, delete-orphan")
    findings: Mapped[list["Finding"]] = relationship(back_populates="session", cascade="all, delete-orphan")
    writeup_versions: Mapped[list["WriteupVersion"]] = relationship(back_populates="session", cascade="all, delete-orphan")
    user_notes: Mapped[list["UserNote"]] = relationship(back_populates="session", cascade="all, delete-orphan")


# ---------------------------------------------------------------------------
# Events — immutable raw evidence
# ---------------------------------------------------------------------------
class Event(Base):
    __tablename__ = "events"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    session_id: Mapped[int] = mapped_column(ForeignKey("sessions.id"), nullable=False)
    source: Mapped[str] = mapped_column(nullable=False)
    timestamp: Mapped[datetime.datetime] = mapped_column(nullable=False)

    # terminal-specific
    command: Mapped[Optional[str]] = mapped_column(nullable=True)
    stdout: Mapped[Optional[str]] = mapped_column(nullable=True)
    stderr: Mapped[Optional[str]] = mapped_column(nullable=True)
    cwd: Mapped[Optional[str]] = mapped_column(nullable=True)

    # browser-specific
    url: Mapped[Optional[str]] = mapped_column(nullable=True)
    http_method: Mapped[Optional[str]] = mapped_column(nullable=True)
    http_status: Mapped[Optional[int]] = mapped_column(nullable=True)

    # filesystem-specific
    file_path: Mapped[Optional[str]] = mapped_column(nullable=True)
    file_action: Mapped[Optional[str]] = mapped_column(nullable=True)

    # screenshot-specific
    screenshot_path: Mapped[Optional[str]] = mapped_column(nullable=True)

    raw_metadata: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)

    __table_args__ = (
        CheckConstraint(
            "source IN ('terminal','browser','filesystem','screenshot','user_note')",
            name="ck_event_source",
        ),
        CheckConstraint(
            "file_action IS NULL OR file_action IN ('created','modified','deleted')",
            name="ck_event_file_action",
        ),
    )

    session: Mapped["Session"] = relationship(back_populates="events")
    evidence_links: Mapped[list["FindingEvidence"]] = relationship(back_populates="event")
    user_notes: Mapped[list["UserNote"]] = relationship(back_populates="related_event")


# ---------------------------------------------------------------------------
# Findings — AI-derived, regenerable
# ---------------------------------------------------------------------------
class Finding(Base):
    __tablename__ = "findings"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    session_id: Mapped[int] = mapped_column(ForeignKey("sessions.id"), nullable=False)
    name: Mapped[str] = mapped_column(nullable=False)
    finding_type: Mapped[Optional[str]] = mapped_column(nullable=True)
    confidence_score: Mapped[Optional[float]] = mapped_column(nullable=True)
    confidence_label: Mapped[Optional[str]] = mapped_column(nullable=True)
    is_successful_path: Mapped[bool] = mapped_column(default=False)
    created_at: Mapped[datetime.datetime] = mapped_column(default=datetime.datetime.utcnow)
    pipeline_version: Mapped[Optional[str]] = mapped_column(nullable=True)

    __table_args__ = (
        CheckConstraint(
            "finding_type IS NULL OR finding_type IN "
            "('vulnerability','credential','access','privilege_escalation','recon','dead_end','other')",
            name="ck_finding_type",
        ),
        CheckConstraint(
            "confidence_label IS NULL OR confidence_label IN ('HIGH','MEDIUM','LOW')",
            name="ck_finding_confidence_label",
        ),
        CheckConstraint(
            "confidence_score IS NULL OR (confidence_score >= 0 AND confidence_score <= 1)",
            name="ck_finding_confidence_score",
        ),
    )

    session: Mapped["Session"] = relationship(back_populates="findings")
    evidence_links: Mapped[list["FindingEvidence"]] = relationship(back_populates="finding", cascade="all, delete-orphan")

    relationships_from: Mapped[list["AttackRelationship"]] = relationship(
        back_populates="from_finding",
        foreign_keys="AttackRelationship.from_finding_id",
        cascade="all, delete-orphan",
    )
    relationships_to: Mapped[list["AttackRelationship"]] = relationship(
        back_populates="to_finding",
        foreign_keys="AttackRelationship.to_finding_id",
        cascade="all, delete-orphan",
    )


# ---------------------------------------------------------------------------
# Finding <-> Event link table (evidence linking)
# ---------------------------------------------------------------------------
class FindingEvidence(Base):
    __tablename__ = "finding_evidence"

    finding_id: Mapped[int] = mapped_column(ForeignKey("findings.id"), primary_key=True)
    event_id: Mapped[int] = mapped_column(ForeignKey("events.id"), primary_key=True)

    finding: Mapped["Finding"] = relationship(back_populates="evidence_links")
    event: Mapped["Event"] = relationship(back_populates="evidence_links")


# ---------------------------------------------------------------------------
# Attack graph edges
# ---------------------------------------------------------------------------
class AttackRelationship(Base):
    __tablename__ = "attack_relationships"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    session_id: Mapped[int] = mapped_column(ForeignKey("sessions.id"), nullable=False)
    from_finding_id: Mapped[int] = mapped_column(ForeignKey("findings.id"), nullable=False)
    to_finding_id: Mapped[int] = mapped_column(ForeignKey("findings.id"), nullable=False)
    relationship_type: Mapped[str] = mapped_column(default="enabled")

    from_finding: Mapped["Finding"] = relationship(back_populates="relationships_from", foreign_keys=[from_finding_id])
    to_finding: Mapped["Finding"] = relationship(back_populates="relationships_to", foreign_keys=[to_finding_id])


# ---------------------------------------------------------------------------
# Write-up versions
# ---------------------------------------------------------------------------
class WriteupVersion(Base):
    __tablename__ = "writeup_versions"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    session_id: Mapped[int] = mapped_column(ForeignKey("sessions.id"), nullable=False)
    version_number: Mapped[int] = mapped_column(nullable=False)
    content_markdown: Mapped[str] = mapped_column(nullable=False)
    generated_at: Mapped[datetime.datetime] = mapped_column(default=datetime.datetime.utcnow)
    completion_percentage: Mapped[Optional[float]] = mapped_column(nullable=True)

    __table_args__ = (
        UniqueConstraint("session_id", "version_number", name="uq_session_version"),
    )

    session: Mapped["Session"] = relationship(back_populates="writeup_versions")
    claims: Mapped[list["WriteupClaim"]] = relationship(back_populates="writeup_version", cascade="all, delete-orphan")


# ---------------------------------------------------------------------------
# Write-up claims (for verification engine)
# ---------------------------------------------------------------------------
class WriteupClaim(Base):
    __tablename__ = "writeup_claims"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    writeup_version_id: Mapped[int] = mapped_column(ForeignKey("writeup_versions.id"), nullable=False)
    claim_text: Mapped[str] = mapped_column(nullable=False)
    supporting_event_ids: Mapped[Optional[list]] = mapped_column(JSON, nullable=True)
    verification_status: Mapped[str] = mapped_column(default="UNVERIFIED")

    __table_args__ = (
        CheckConstraint(
            "verification_status IN ('VERIFIED','UNVERIFIED','PARTIAL')",
            name="ck_claim_verification_status",
        ),
    )

    writeup_version: Mapped["WriteupVersion"] = relationship(back_populates="claims")


# ---------------------------------------------------------------------------
# User notes (optional async reasoning capture)
# ---------------------------------------------------------------------------
class UserNote(Base):
    __tablename__ = "user_notes"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    session_id: Mapped[int] = mapped_column(ForeignKey("sessions.id"), nullable=False)
    related_event_id: Mapped[Optional[int]] = mapped_column(ForeignKey("events.id"), nullable=True)
    note_text: Mapped[str] = mapped_column(nullable=False)
    created_at: Mapped[datetime.datetime] = mapped_column(default=datetime.datetime.utcnow)

    session: Mapped["Session"] = relationship(back_populates="user_notes")
    related_event: Mapped[Optional["Event"]] = relationship(back_populates="user_notes")
    
# ---------------------------------------------------------------------------
# Processed-event tracking — separate from findings, since "analyzed but
# produced no finding" and "never analyzed" must be distinguishable.
# ---------------------------------------------------------------------------
class ProcessedEvent(Base):
    __tablename__ = "processed_events"

    event_id: Mapped[int] = mapped_column(ForeignKey("events.id"), primary_key=True)
    processed_at: Mapped[datetime.datetime] = mapped_column(default=datetime.datetime.utcnow)
    pipeline_version: Mapped[Optional[str]] = mapped_column(nullable=True)