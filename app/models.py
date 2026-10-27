"""
Leadline Database Models
Phase 7: Event Database - SQLAlchemy ORM models
"""
from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, Text, Boolean, Float, JSON
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from app.db import Base


class Target(Base):
    """Target model - Phase 2: Target Management"""
    __tablename__ = "targets"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(255), nullable=False, index=True)
    url = Column(String(512), nullable=False, unique=True, index=True)
    notes = Column(Text, nullable=True)
    is_active = Column(Boolean, default=True)
    # Headers merged into every outbound request the scanner makes against
    # this target -- e.g. an Authorization/Cookie header for auth-gated
    # targets, or a custom X-Api-Key. Stored as a plain {header: value} dict.
    custom_headers = Column(JSON, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())

    # Relationships
    scans = relationship("Scan", back_populates="target", cascade="all, delete-orphan")

    def __repr__(self):
        return f"<Target(id={self.id}, name='{self.name}', url='{self.url}')>"


class Scan(Base):
    """Scan model - tracks reconnaissance runs"""
    __tablename__ = "scans"

    id = Column(Integer, primary_key=True, index=True)
    target_id = Column(Integer, ForeignKey("targets.id"), nullable=False)
    status = Column(String(50), default="pending")  # pending, running, completed, failed, stopped
    progress = Column(Float, default=0.0)  # 0-100 percentage
    current_phase = Column(String(100), nullable=True)
    started_at = Column(DateTime(timezone=True), nullable=True)
    completed_at = Column(DateTime(timezone=True), nullable=True)
    error_message = Column(Text, nullable=True)
    # Request pacing config for this scan run. evasion_enabled toggles
    # User-Agent rotation + inter-request jitter (see app/recon/base.py);
    # request_delay overrides the global REQUEST_DELAY default when set.
    # The field names are kept for database/API compatibility.
    evasion_enabled = Column(Boolean, default=True)
    request_delay = Column(Float, nullable=True)
    enable_external_lookups = Column(Boolean, default=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    # Relationships
    target = relationship("Target", back_populates="scans")
    events = relationship("ScanEvent", back_populates="scan", cascade="all, delete-orphan")
    findings = relationship("Finding", back_populates="scan", cascade="all, delete-orphan")
    graph_nodes = relationship("GraphNode", back_populates="scan", cascade="all, delete-orphan")

    def __repr__(self):
        return f"<Scan(id={self.id}, target_id={self.target_id}, status='{self.status}')>"


class ScanEvent(Base):
    """ScanEvent model - Phase 7: stores per-phase results"""
    __tablename__ = "scan_events"

    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, ForeignKey("scans.id"), nullable=False)
    phase_name = Column(String(100), nullable=False)  # e.g., "dns_discovery", "http_fingerprinting"
    phase_order = Column(Integer, nullable=False)  # execution order
    status = Column(String(50), default="pending")  # pending, running, completed, failed
    started_at = Column(DateTime(timezone=True), nullable=True)
    completed_at = Column(DateTime(timezone=True), nullable=True)
    result_data = Column(JSON, nullable=True)  # structured phase results
    # Set explicitly at write time from the phase's own findings list.
    # NOT derivable later from result_data -- findings are stored
    # separately in the Finding table (no phase-attributing column there),
    # so by the time a report is built there's no way to reconstruct which
    # phase produced how many findings unless it was recorded here first.
    findings_count = Column(Integer, default=0)
    error_message = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    # Relationships
    scan = relationship("Scan", back_populates="events")

    def __repr__(self):
        return f"<ScanEvent(id={self.id}, scan_id={self.scan_id}, phase='{self.phase_name}')>"


class Finding(Base):
    """Finding model - security findings from scans"""
    __tablename__ = "findings"

    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, ForeignKey("scans.id"), nullable=False)
    finding_type = Column(String(100), nullable=False)  # endpoint, api, vulnerability, etc.
    severity = Column(String(20), default="info")  # info, low, medium, high, critical
    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    location = Column(String(512), nullable=True)  # URL or path
    evidence = Column(Text, nullable=True)
    remediation = Column(Text, nullable=True)
    extra_data = Column(JSON, nullable=True)  # additional structured data
    is_false_positive = Column(Boolean, default=False)
    # Lightweight triage workflow for the target timeline. Kept separate from
    # is_false_positive so existing reports/API clients keep working.
    triage_status = Column(String(30), default="open")  # open, acknowledged, false_positive
    triage_note = Column(Text, nullable=True)
    triaged_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    # Relationships
    scan = relationship("Scan", back_populates="findings")

    def __repr__(self):
        return f"<Finding(id={self.id}, type='{self.finding_type}', severity='{self.severity}')>"


class GraphNode(Base):
    """GraphNode model - Phase 8: Attack Surface Graph nodes and edges"""
    __tablename__ = "graph_nodes"

    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, ForeignKey("scans.id"), nullable=False)
    node_id = Column(String(255), nullable=False)  # unique identifier for the node
    node_type = Column(String(50), nullable=False)  # root, endpoint, api, parameter, etc.
    label = Column(String(255), nullable=False)
    parent_id = Column(String(255), nullable=True)  # for tree structure
    depth = Column(Integer, default=0)
    extra_data = Column(JSON, nullable=True)  # additional node data
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    # Relationships
    scan = relationship("Scan", back_populates="graph_nodes")

    def __repr__(self):
        return f"<GraphNode(id={self.id}, node_id='{self.node_id}', type='{self.node_type}')>"
