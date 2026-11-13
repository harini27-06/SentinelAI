from datetime import datetime, timezone

from sqlalchemy import Boolean, Column, DateTime, Float, ForeignKey, Integer, JSON, String, Table, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


simulation_events = Table(
    "simulation_events",
    Base.metadata,
    Column("simulation_id", String(100), ForeignKey("simulations.id"), primary_key=True),
    Column("event_id", String(150), ForeignKey("events.id"), primary_key=True),
)


def utcnow():
    return datetime.now(timezone.utc)


class Endpoint(Base):
    __tablename__ = "endpoints"
    id: Mapped[str] = mapped_column(String(100), primary_key=True)
    hostname: Mapped[str | None] = mapped_column(String(255))
    platform: Mapped[str | None] = mapped_column(String(100))
    status: Mapped[str] = mapped_column(String(32), default="online")
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class Agent(Base):
    __tablename__ = "agents"
    id: Mapped[str] = mapped_column(String(100), primary_key=True)
    agent_type: Mapped[str] = mapped_column(String(64), unique=True)
    status: Mapped[str] = mapped_column(String(32), default="active")
    description: Mapped[str] = mapped_column(Text, default="")
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class Event(Base):
    __tablename__ = "events"
    id: Mapped[str] = mapped_column(String(150), primary_key=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    endpoint_id: Mapped[str] = mapped_column(ForeignKey("endpoints.id"), index=True)
    agent_type: Mapped[str] = mapped_column(String(64), index=True)
    event_type: Mapped[str] = mapped_column(String(100), default="telemetry")
    source: Mapped[str] = mapped_column(String(64), default="api")
    scenario: Mapped[str | None] = mapped_column(String(100))
    severity: Mapped[str] = mapped_column(String(16), default="info")
    label: Mapped[int | None] = mapped_column(Integer)
    attack_cat: Mapped[str | None] = mapped_column(String(100))
    payload: Mapped[dict] = mapped_column(JSON, default=dict)
    synthetic: Mapped[bool] = mapped_column(Boolean, default=False)
    alerts: Mapped[list["Alert"]] = relationship(back_populates="event")
    simulations: Mapped[list["Simulation"]] = relationship(
        secondary=simulation_events, back_populates="events",
    )


class Alert(Base):
    __tablename__ = "alerts"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    event_id: Mapped[str] = mapped_column(ForeignKey("events.id"), index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    severity: Mapped[str] = mapped_column(String(16))
    rule: Mapped[str] = mapped_column(String(100))
    description: Mapped[str] = mapped_column(Text)
    score: Mapped[float | None] = mapped_column(Float)
    status: Mapped[str] = mapped_column(String(32), default="open")
    event: Mapped[Event] = relationship(back_populates="alerts")


class Simulation(Base):
    __tablename__ = "simulations"
    id: Mapped[str] = mapped_column(String(100), primary_key=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    scenario: Mapped[str] = mapped_column(String(100))
    status: Mapped[str] = mapped_column(String(32), default="completed")
    event_count: Mapped[int] = mapped_column(Integer, default=0)
    alert_count: Mapped[int] = mapped_column(Integer, default=0)
    results: Mapped[dict] = mapped_column(JSON, default=dict)
    events: Mapped[list[Event]] = relationship(
        secondary=simulation_events, back_populates="simulations",
    )


class Feedback(Base):
    __tablename__ = "feedback"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    alert_id: Mapped[int] = mapped_column(ForeignKey("alerts.id"), index=True)
    verdict: Mapped[str] = mapped_column(String(32))
    notes: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class AuditLog(Base):
    __tablename__ = "audit_logs"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    action: Mapped[str] = mapped_column(String(100), index=True)
    actor: Mapped[str] = mapped_column(String(100), default="api")
    resource_id: Mapped[str | None] = mapped_column(String(150))
    details: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class Evaluation(Base):
    __tablename__ = "evaluations"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    model_name: Mapped[str] = mapped_column(String(100))
    metrics: Mapped[dict] = mapped_column(JSON, default=dict)
    dataset: Mapped[str] = mapped_column(String(150))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class AppSetting(Base):
    __tablename__ = "app_settings"
    key: Mapped[str] = mapped_column(String(100), primary_key=True)
    value: Mapped[dict] = mapped_column(JSON, default=dict)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)
