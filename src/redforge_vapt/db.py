import os
from datetime import UTC, datetime

from sqlalchemy import JSON, DateTime, ForeignKey, Integer, String, Text, create_engine
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship, sessionmaker


def now():
    return datetime.now(UTC)


class Base(DeclarativeBase):
    pass


class Engagement(Base):
    __tablename__ = "engagements"
    id: Mapped[str] = mapped_column(String(100), primary_key=True)
    client: Mapped[str] = mapped_column(String(200))
    operator: Mapped[str] = mapped_column(String(200))
    scope: Mapped[dict] = mapped_column(JSON)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    scans: Mapped[list["Scan"]] = relationship(back_populates="engagement")


class Scan(Base):
    __tablename__ = "scans"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    engagement_id: Mapped[str] = mapped_column(ForeignKey("engagements.id"), index=True)
    profile: Mapped[str] = mapped_column(String(30))
    mode: Mapped[str] = mapped_column(String(20))
    status: Mapped[str] = mapped_column(String(30))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    tool_status: Mapped[dict] = mapped_column(JSON, default=dict)
    engagement: Mapped[Engagement] = relationship(back_populates="scans")
    findings: Mapped[list["Finding"]] = relationship(back_populates="scan")


class Finding(Base):
    __tablename__ = "findings"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    scan_id: Mapped[str] = mapped_column(ForeignKey("scans.id"), index=True)
    engagement_id: Mapped[str] = mapped_column(ForeignKey("engagements.id"), index=True)
    fingerprint: Mapped[str] = mapped_column(String(64), index=True)
    title: Mapped[str] = mapped_column(String(500))
    description: Mapped[str] = mapped_column(Text, default="")
    asset: Mapped[str] = mapped_column(String(500))
    location: Mapped[str] = mapped_column(String(500), default="")
    severity: Mapped[str] = mapped_column(String(20))
    confidence: Mapped[str] = mapped_column(String(20), default="unknown")
    verification: Mapped[str] = mapped_column(String(30), default="unverified")
    references: Mapped[list] = mapped_column(JSON, default=list)
    sources: Mapped[list] = mapped_column(JSON, default=list)
    evidence: Mapped[list] = mapped_column(JSON, default=list)
    remediation: Mapped[str] = mapped_column(Text, default="")
    first_detected: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    last_detected: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    scan: Mapped[Scan] = relationship(back_populates="findings")


class Audit(Base):
    __tablename__ = "audit_logs"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    actor: Mapped[str] = mapped_column(String(200))
    action: Mapped[str] = mapped_column(String(80))
    engagement_id: Mapped[str | None] = mapped_column(String(100))
    details: Mapped[dict] = mapped_column(JSON, default=dict)


def database_url():
    return os.environ.get("REDFORGE_DATABASE_URL", "sqlite:///./redforge.db")


def connect(url=None):
    engine = create_engine(url or database_url(), future=True)
    return engine, sessionmaker(engine, expire_on_commit=False)
