from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
import csv
import json
import logging
from pathlib import Path
from time import perf_counter
from uuid import uuid4

from fastapi import Depends, FastAPI, HTTPException, Query, Request
from fastapi.exceptions import RequestValidationError
from fastapi.encoders import jsonable_encoder
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.config import ALLOWED_ORIGINS, CORRELATION_WINDOW_SECONDS
from app.database import Base, engine, get_db
from app.models import AppSetting, Agent, Alert, AuditLog, Endpoint, Evaluation, Event, Feedback, Simulation, utcnow
from app.schemas import (
    AgentRegistration, AlertUpdate, EventCreate, EventOut, FeedbackCreate, FeedbackRequest,
    SettingsUpdate, SimulationCreate, SimulationRequest,
)
from app.services.agents import event_agent_type, get_agent, list_agents
from app.services.detection import AGENT_TYPES, detect, model_status

logger = logging.getLogger(__name__)
METRICS_PATH = Path(__file__).resolve().parents[1] / "artifacts" / "training_metrics.json"
DEFAULT_SETTINGS = {
    "failed_login_threshold": 5,
    "login_frequency_threshold": 15,
    "unauthorized_request_threshold": 5,
    "correlation_window_minutes": max(1, CORRELATION_WINDOW_SECONDS // 60),
    "api_requests_per_minute": 300,
    "file_modifications": 20,
    "network_unique_ports": 15,
    "dos_rate_threshold": 1000,
    "system_resource_threshold": 95,
    "default_simulation_event_count": 12,
}


def get_detection_settings(db: Session):
    row = db.get(AppSetting, "detection_thresholds")
    return {**DEFAULT_SETTINGS, **(row.value if row else {})}

@asynccontextmanager
async def lifespan(application):
    Base.metadata.create_all(bind=engine)
    with Session(engine) as db:
        for agent_type, description in AGENT_TYPES.items():
            if not db.scalar(select(Agent).where(Agent.agent_type == agent_type)):
                db.add(Agent(id=agent_type, agent_type=agent_type, description=description))
        if db.get(AppSetting, "detection_thresholds") is None:
            db.add(AppSetting(key="detection_thresholds", value=DEFAULT_SETTINGS))
        db.commit()
        record_evaluation(db)
    yield


app = FastAPI(title="SentinelAI API", version="1.0.0", description="Synthetic-data security monitoring prototype",
              lifespan=lifespan)
app.add_middleware(
    CORSMiddleware,
    allow_origins=[origin.strip() for origin in ALLOWED_ORIGINS if origin.strip()],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.exception_handler(RequestValidationError)
async def validation_error_handler(request, exc):
    details = [
        {"location": error.get("loc"), "message": error.get("msg"), "type": error.get("type")}
        for error in exc.errors()
    ]
    return JSONResponse(status_code=422, content=jsonable_encoder(
        {"error": {"code": "validation_error", "message": "Request validation failed", "details": details}}))


@app.exception_handler(IntegrityError)
async def integrity_error_handler(request, exc):
    return JSONResponse(status_code=409, content={"error": {"code": "conflict", "message": "Resource already exists or violates a database constraint"}})


@app.exception_handler(HTTPException)
async def http_error_handler(request: Request, exc: HTTPException):
    detail = exc.detail if isinstance(exc.detail, dict) else {"message": str(exc.detail)}
    return JSONResponse(status_code=exc.status_code, content={"error": {"code": detail.get("code", "http_error"),
                                                                        "message": detail.get("message", "Request failed"),
                                                                        "details": detail.get("details")}},
                        headers=exc.headers)


@app.exception_handler(Exception)
async def unexpected_error_handler(request: Request, exc: Exception):
    logger.error(
        "Unhandled backend error for %s %s", request.method, request.url.path,
        exc_info=(type(exc), exc, exc.__traceback__),
    )
    return JSONResponse(status_code=500, content={"error": {"code": "internal_error", "message": "Internal server error"}})


def process_event(db: Session, body: EventCreate, synthetic=None, commit=True):
    agent_handler = get_agent(body.agent_type)
    if agent_handler is None:
        raise HTTPException(status_code=422, detail={
            "code": "invalid_agent_type", "message": f"Unsupported agent type: {body.agent_type}",
        })
    if not agent_handler.supports(body.event_type):
        raise HTTPException(status_code=422, detail={
            "code": "unsupported_event_type",
            "message": f"{body.agent_type} does not accept event type {body.event_type}",
        })
    event_id = body.id or body.event_id or str(uuid4())
    timestamp = body.timestamp or datetime.now(timezone.utc)
    endpoint = db.get(Endpoint, body.endpoint_id)
    if not endpoint:
        db.add(Endpoint(id=body.endpoint_id))
    else:
        endpoint.last_seen = datetime.now(timezone.utc)
        endpoint.status = "online"
    agent = db.scalar(select(Agent).where(Agent.agent_type == body.agent_type))
    if agent is None:
        db.add(Agent(id=body.agent_id or body.agent_type, agent_type=body.agent_type,
                     description=AGENT_TYPES.get(body.agent_type, "Ingested telemetry agent.")))
    else:
        agent.last_seen = datetime.now(timezone.utc)
        agent.status = "active"
    event = Event(
        id=event_id, timestamp=timestamp, endpoint_id=body.endpoint_id, agent_type=body.agent_type,
        event_type=body.event_type, source=body.source, scenario=body.scenario, severity=body.severity,
        label=body.label, attack_cat=body.attack_cat,
        payload=body.normalized_payload(), synthetic=body.synthetic if synthetic is None else synthetic,
    )
    db.add(event)
    db.flush()
    settings = get_detection_settings(db)
    agent_result = agent_handler.analyze(event, settings)
    if not agent_result["accepted"]:
        raise HTTPException(status_code=422, detail={
            "code": "unsupported_event_type", "message": agent_result["error"],
        })
    matches = agent_result["matches"]
    model_score = agent_result["model_score"]
    matches.extend(correlate_findings(db, event, matches, settings))
    finding_rows = list(agent_result["findings"])
    finding_rows.extend({
        "finding_id": match["rule"],
        "agent_id": agent_handler.agent_id,
        "agent_type": agent_handler.agent_type,
        "rule": match["rule"],
        "severity": match["severity"],
        "explanation": match["description"],
        "score": match.get("score"),
        "detection_method": "cross_event_correlation",
    } for match in matches if match["rule"] == "cross_agent_correlation")
    event.payload = {
        **(event.payload or {}),
        "_sentinelai": {
            "agent_id": agent_result["agent_id"],
            "agent_type": agent_result["agent_type"],
            "agent_status": agent_result["status"],
            "processing_time_ms": agent_result["processing_time_ms"],
            "findings": finding_rows,
            "model_score": agent_result["model_score"],
            "anomaly_score": agent_result["anomaly_score"],
            "model_version": agent_result["model_version"],
            "classifier_prediction": agent_result["classifier_prediction"],
            "anomaly_decision": agent_result["anomaly_decision"],
            "risk_score": max(
                ({"info": 0, "low": 10, "medium": 40, "high": 70, "critical": 90}.get(match["severity"], 0)
                 for match in matches),
                default=0,
            ),
        },
    }
    created_alerts = []
    for match in matches:
        alert = Alert(event_id=event.id, severity=match["severity"], rule=match["rule"],
                      description=match["description"], score=match.get("score", model_score))
        db.add(alert)
        created_alerts.append(alert)
    db.add(AuditLog(action="event_ingested", resource_id=event.id, details={
        "source": event.source, "agent_id": agent_result["agent_id"],
        "agent_processing_time_ms": agent_result["processing_time_ms"],
    }))
    if commit:
        db.commit()
        db.refresh(event)
        for alert in created_alerts:
            db.refresh(alert)
    else:
        db.flush()
    return event, created_alerts


def correlate_findings(db: Session, event: Event, matches, settings):
    current_signals = {
        (event.agent_type, match["rule"])
        for match in matches
        if match["rule"] not in {"cross_agent_correlation", "correlated_signals"}
    }
    if not current_signals:
        return []
    correlation_window = settings["correlation_window_minutes"] * 60
    start_time = event.timestamp - timedelta(seconds=correlation_window)
    previous_alerts = db.scalars(
        select(Alert).join(Event).where(
            Event.endpoint_id == event.endpoint_id,
            Event.source == event.source,
            Event.timestamp >= start_time,
            Event.timestamp <= event.timestamp,
            Event.id != event.id,
            Alert.rule.not_in(["cross_agent_correlation", "correlated_signals"]),
        )
    ).all()
    signals = set(current_signals)
    for alert in previous_alerts:
        signals.add((alert.event.agent_type, alert.rule))
    agent_types = {agent_type for agent_type, _ in signals}
    rule_names = {rule for _, rule in signals}
    if len(agent_types) < 2 or len(rule_names) < 2:
        return []
    duplicate = db.scalar(
        select(Alert.id).join(Event).where(
            Event.endpoint_id == event.endpoint_id,
            Event.source == event.source,
            Event.timestamp >= start_time,
            Event.timestamp <= event.timestamp,
            Alert.rule == "cross_agent_correlation",
        ).limit(1)
    )
    if duplicate is not None:
        return []
    severity = "critical" if len(agent_types) >= 3 else "high"
    explanation = (
        "Correlated distinct findings across agents: "
        + ", ".join(sorted(f"{agent}:{rule}" for agent, rule in signals))
        + f" within {settings['correlation_window_minutes']} minutes."
    )
    return [{
        "rule": "cross_agent_correlation",
        "severity": severity,
        "description": explanation,
        "score": None,
    }]


def alert_dict(alert, event=None):
    event = event or alert.event
    detection = (event.payload or {}).get("_sentinelai", {}) if event else {}
    method = (
        "trained_classifier" if alert.rule == "trained_model" else
        "isolation_forest" if alert.rule == "isolation_forest_anomaly" else
        "cross_event_correlation" if alert.rule == "cross_agent_correlation" else
        "deterministic_rules"
    )
    recommendation = (
        "Prioritize analyst review and validate related evidence."
        if alert.severity in {"critical", "high"} else
        "Review the event context and corroborate this signal before escalation."
    )
    return {
        "id": alert.id,
        "alert_id": alert.id,
        "event_id": alert.event_id,
        "title": alert.description,
        "message": alert.description,
        "explanation": alert.description,
        "severity": alert.severity,
        "rule": alert.rule,
        "detection_method": method,
        "score": alert.score,
        "risk_score": alert.score,
        "model_score": detection.get("model_score"),
        "anomaly_score": detection.get("anomaly_score"),
        "model_version": detection.get("model_version"),
        "classifier_prediction": detection.get("classifier_prediction"),
        "anomaly_decision": detection.get("anomaly_decision"),
        "recommended_action": recommendation,
        "status": alert.status,
        "created_at": alert.created_at.isoformat() if alert.created_at else None,
        "timestamp": (
            event.timestamp.isoformat() if event else
            alert.created_at.isoformat() if alert.created_at else None
        ),
        "endpoint_id": event.endpoint_id if event else None,
    }


def evaluation_report():
    if not METRICS_PATH.is_file():
        return None
    try:
        return json.loads(METRICS_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        logger.error("Could not read model evaluation report %s: %s", METRICS_PATH, error)
        return None


def record_evaluation(db: Session):
    report = evaluation_report()
    if report is None:
        return None
    metrics = {
        "split": report.get("split"),
        "random_forest": report.get("random_forest"),
        "isolation_forest_normal_only_fit": report.get("isolation_forest_normal_only_fit"),
        "attack_categories": report.get("attack_categories"),
        "warning": report.get("warning"),
    }
    previous = db.scalar(
        select(Evaluation).where(Evaluation.model_name == "SentinelAI detection models")
        .order_by(Evaluation.created_at.desc())
    )
    if previous is not None and previous.metrics == metrics:
        return previous
    evaluation = Evaluation(
        model_name="SentinelAI detection models",
        metrics=metrics,
        dataset=report.get("dataset", "synthetic"),
    )
    db.add(evaluation)
    db.commit()
    return evaluation


def synthetic_flow_payload(high_rate=False):
    dataset_path = Path(__file__).resolve().parents[1] / "data" / "raw" / "sentinelai_synthetic_cleaned.csv"
    excluded = {"label", "attack_cat", "event_id", "timestamp", "endpoint_id", "agent_type",
                "source", "scenario", "synthetic", "id"}
    if dataset_path.is_file():
        with dataset_path.open(encoding="utf-8-sig", newline="") as stream:
            for row in csv.DictReader(stream):
                if row.get("label") == "0":
                    payload = {
                        key: _csv_value(value)
                        for key, value in row.items()
                        if key.lower() not in excluded
                    }
                    break
            else:
                payload = {}
    else:
        payload = {}
    if not payload:
        payload = {
            "dur": 0.35, "proto": "tcp", "service": "ftp", "state": "REQ", "spkts": 8, "dpkts": 4,
            "sbytes": 297, "dbytes": 96, "rate": 33.44, "sttl": 191, "dttl": 142, "sload": 827.7,
            "dload": 267.5, "sloss": 0, "dloss": 0, "sinpkt": 0.04, "dinpkt": 0.08,
            "sjit": 0.28, "djit": 1.01, "swin": 1024, "dwin": 0, "tcprtt": 0.014,
            "synack": 0.004, "ackdat": 0.008, "smean": 37.1, "dmean": 24.0, "trans_depth": 0,
            "response_body_len": 0, "ct_srv_src": 9, "ct_state_ttl": 2, "ct_dst_ltm": 0,
            "ct_src_dport_ltm": 4, "ct_dst_sport_ltm": 7, "ct_dst_src_ltm": 1, "is_ftp_login": 0,
            "ct_ftp_cmd": 0, "ct_flw_http_mthd": 0, "ct_src_ltm": 4, "ct_srv_dst": 8,
            "is_sm_ips_ports": 0,
        }
    if high_rate:
        payload.update({"rate": 5000.0, "sload": 1000000.0, "spkts": 500, "ct_src_ltm": 100})
    return payload


def _csv_value(value):
    try:
        number = float(value)
    except (ValueError, TypeError):
        return value
    return int(number) if number.is_integer() else number


def _simulation_event(scenario, parameters):
    if scenario == "normal_login":
        return "login_agent", "login_success", {"failed_logins": 0, "login_frequency": 1}
    if scenario == "brute_force_login":
        return "login_agent", "login_failure_burst", {
            "failed_logins": max(1, int(parameters.get("failure_count", 12))),
            "source_ip": "192.0.2.10",
        }
    if scenario == "normal_network":
        return "network_agent", "network_flow", synthetic_flow_payload()
    if scenario == "dos_spike":
        payload = synthetic_flow_payload(high_rate=True)
        payload["rate"] = max(1, int(parameters.get("dos_rate", 5000)))
        return "network_agent", "network_flow", payload
    if scenario == "api_burst":
        return "api_agent", "api_request", {
            "requests_per_minute": max(1, int(parameters.get("request_rate", 180))),
            "status_code": 429,
            "unauthorized_requests": max(1, int(parameters.get("unauthorized_requests", 8))),
        }
    if scenario == "file_burst":
        return "file_agent", "file_integrity", {
            "file_changes": max(1, int(parameters.get("modification_count", 20))),
            "access_pattern": "synthetic_burst",
        }
    if scenario == "system_activity":
        return "system_agent", "system_metrics", {
            "cpu_percent": max(1, int(parameters.get("cpu_percent", 99))),
            "memory_percent": max(1, int(parameters.get("memory_percent", 96))),
        }
    return "correlation_agent", "correlated_risk_signals", {
        "indicators": ["repeated_login_failures", "network_scan", "api_abuse"],
    }


def _novel_event(index):
    patterns = [
        ("login_agent", "login_failure_burst", {"failed_logins": 5, "source_ip": "192.0.2.21"}),
        ("system_agent", "system_metrics", {"cpu_percent": 96, "memory_percent": 68}),
        ("api_agent", "api_request", {"requests_per_minute": 300, "status_code": 429}),
    ]
    return patterns[index % len(patterns)]


@app.get("/health")
def health(db: Session = Depends(get_db)):
    db.execute(select(1))
    return {"status": "ok", "service": "sentinelai-backend"}


@app.get("/api/v1/agents")
def get_agents():
    return {"agents": list_agents()}


@app.get("/api/v1/endpoints")
def get_endpoints(db: Session = Depends(get_db)):
    endpoints = db.scalars(select(Endpoint).order_by(Endpoint.id)).all()
    return {"endpoints": endpoints, "count": len(endpoints)}


@app.post("/api/v1/events", status_code=201)
def ingest_event(body: EventCreate, db: Session = Depends(get_db)):
    event, alerts = process_event(db, body)
    return {"event": EventOut.model_validate(event), "alerts": alerts, "alert_count": len(alerts)}


@app.get("/api/v1/events")
def get_events(db: Session = Depends(get_db), limit: int = Query(100, ge=1, le=500),
               offset: int = Query(0, ge=0), endpoint_id: str | None = None):
    stmt = select(Event).order_by(Event.timestamp.desc()).limit(limit).offset(offset)
    if endpoint_id:
        stmt = stmt.where(Event.endpoint_id == endpoint_id)
    events = db.scalars(stmt).all()
    return {"events": [EventOut.model_validate(event) for event in events], "count": len(events)}


@app.get("/api/v1/alerts")
def get_alerts(db: Session = Depends(get_db), limit: int = Query(100, ge=1, le=500),
               offset: int = Query(0, ge=0), status: str | None = None):
    stmt = select(Alert).order_by(Alert.created_at.desc()).limit(limit).offset(offset)
    if status:
        stmt = stmt.where(Alert.status == status)
    alerts = db.scalars(stmt).all()
    return {"alerts": alerts, "count": len(alerts)}


@app.post("/api/v1/simulations", status_code=201)
def run_simulation(body: SimulationCreate, db: Session = Depends(get_db)):
    simulation_id = str(uuid4())
    count = 0
    alert_count = 0
    per_event = []
    event_objects = []
    signals = {
        "login_attack": {"event_type": "login_failure_burst", "failed_logins": 10, "source_ip": "192.0.2.10"},
        "network_scan": {"event_type": "network_flow", "unique_ports": 30, "connections": 100},
        "file_tampering": {"event_type": "file_integrity", "file_changes": 25, "ransomware_note": True},
        "api_abuse": {"event_type": "api_request", "requests_per_minute": 500, "status_code": 429},
        "system_anomaly": {"event_type": "system_metrics", "cpu_percent": 99, "memory_percent": 96},
        "correlated_activity": {"event_type": "correlated_risk_signals",
                                "indicators": ["repeated_login_failures", "network_scan", "api_abuse"]},
    }
    for _ in range(body.count):
        payload = signals[body.scenario]
        event_body = EventCreate(endpoint_id=body.endpoint_id, agent_type=event_agent_type(body.scenario),
                                 event_type=payload["event_type"], source="simulation",
                                 scenario=body.scenario, severity="high", synthetic=True, payload=payload)
        event, alerts = process_event(db, event_body, synthetic=True)
        event_objects.append(event)
        count += 1
        alert_count += len(alerts)
        per_event.append({"event_id": event.id, "alert_ids": [alert.id for alert in alerts]})
    simulation = Simulation(id=simulation_id, scenario=body.scenario, event_count=count,
                            alert_count=alert_count, results={"events": per_event, "synthetic_only": True})
    db.add(simulation)
    db.flush()
    simulation.events.extend(event_objects)
    db.add(AuditLog(action="simulation_run", resource_id=simulation_id,
                    details={"scenario": body.scenario, "synthetic_only": True, "event_count": count}))
    db.commit()
    return {"id": simulation.id, "scenario": simulation.scenario, "status": simulation.status,
            "event_count": count, "alert_count": alert_count, "results": simulation.results}


@app.get("/api/v1/simulations")
def get_simulations(db: Session = Depends(get_db)):
    simulations = db.scalars(select(Simulation).order_by(Simulation.created_at.desc())).all()
    return {"simulations": simulations, "count": len(simulations)}


@app.post("/api/v1/alerts/{alert_id}/feedback", status_code=201)
def submit_feedback(alert_id: int, body: FeedbackCreate, db: Session = Depends(get_db)):
    alert = db.get(Alert, alert_id)
    if alert is None:
        raise HTTPException(status_code=404, detail={"code": "not_found", "message": "Alert not found"})
    feedback = Feedback(alert_id=alert_id, verdict=body.verdict, notes=body.notes)
    db.add(feedback)
    db.add(AuditLog(action="alert_feedback", resource_id=str(alert_id), details={"verdict": body.verdict}))
    if body.verdict in {"benign", "false_positive"}:
        alert.status = "false_positive"
    elif body.verdict in {"malicious", "true_positive"}:
        alert.status = "confirmed"
    db.commit()
    db.refresh(feedback)
    return feedback


@app.get("/api/v1/analytics")
def analytics(db: Session = Depends(get_db)):
    event_count = db.scalar(select(func.count()).select_from(Event)) or 0
    alert_count = db.scalar(select(func.count()).select_from(Alert)) or 0
    open_alerts = db.scalar(select(func.count()).select_from(Alert).where(Alert.status == "open")) or 0
    endpoint_count = db.scalar(select(func.count()).select_from(Endpoint)) or 0
    by_severity = db.execute(select(Alert.severity, func.count()).group_by(Alert.severity)).all()
    by_agent = db.execute(select(Event.agent_type, func.count()).group_by(Event.agent_type)).all()
    return {"events": event_count, "alerts": alert_count, "open_alerts": open_alerts,
            "endpoints": endpoint_count, "alerts_by_severity": dict(by_severity),
            "events_by_agent": dict(by_agent), "model": model_status()}


@app.get("/api/v1/model/status")
def get_model_status():
    return model_status()


@app.get("/api/v1/evaluations")
def get_evaluations(db: Session = Depends(get_db)):
    evaluations = db.scalars(select(Evaluation).order_by(Evaluation.created_at.desc())).all()
    return {"evaluations": evaluations, "count": len(evaluations)}


@app.get("/api/health")
def api_health(db: Session = Depends(get_db)):
    db.execute(select(1))
    return {"status": "ok", "service": "sentinelai-backend", "mode": "synthetic"}


@app.get("/api/dashboard/stats")
def dashboard_stats(db: Session = Depends(get_db)):
    event_count = db.scalar(select(func.count()).select_from(Event)) or 0
    alert_count = db.scalar(select(func.count()).select_from(Alert)) or 0
    open_alerts = db.scalar(select(func.count()).select_from(Alert).where(Alert.status == "open")) or 0
    endpoint_count = db.scalar(select(func.count()).select_from(Endpoint)) or 0
    active_agents = db.scalar(select(func.count()).select_from(Agent).where(Agent.status == "active")) or 0
    by_severity = dict(db.execute(select(Alert.severity, func.count()).group_by(Alert.severity)).all())
    since = datetime.now(timezone.utc) - timedelta(days=6)
    events = db.scalars(select(Event).where(Event.timestamp >= since)).all()
    alerts = db.scalars(select(Alert).where(Alert.created_at >= since)).all()
    buckets = {}
    for offset in range(6, -1, -1):
        day = (datetime.now(timezone.utc) - timedelta(days=offset)).date().isoformat()
        buckets[day] = {"date": day, "events": 0, "alerts": 0}
    for event in events:
        day = event.timestamp.date().isoformat()
        if day in buckets:
            buckets[day]["events"] += 1
    for alert in alerts:
        day = alert.created_at.date().isoformat()
        if day in buckets:
            buckets[day]["alerts"] += 1
    return {
        "health": "operational",
        "system_health": "operational",
        "endpoint_count": endpoint_count,
        "active_agents": active_agents,
        "events_processed": event_count,
        "total_events": event_count,
        "alert_count": alert_count,
        "total_alerts": alert_count,
        "open_alerts": open_alerts,
        "alerts_by_severity": by_severity,
        "threat_activity": list(buckets.values()),
        "model_status": model_status(),
        "synthetic_only": True,
    }


@app.get("/api/agents")
def api_agents(
    db: Session = Depends(get_db),
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
):
    agents = db.scalars(select(Agent).order_by(Agent.agent_type).limit(limit).offset(offset)).all()
    total = db.scalar(select(func.count()).select_from(Agent)) or 0
    agent_rows = []
    for agent in agents:
        recent_findings = db.scalars(
            select(Alert).join(Event).where(Event.agent_type == agent.agent_type)
            .order_by(Alert.created_at.desc()).limit(5)
        ).all()
        agent_rows.append({
            "id": agent.id,
            "agent_id": agent.id,
            "agent_type": agent.agent_type,
            "name": agent.agent_type,
            "status": agent.status,
            "description": agent.description,
            "last_seen": agent.last_seen,
            "events_processed": db.scalar(
                select(func.count()).select_from(Event).where(Event.agent_type == agent.agent_type)
            ) or 0,
            "findings_count": db.scalar(
                select(func.count()).select_from(Alert).join(Event).where(Event.agent_type == agent.agent_type)
            ) or 0,
            "recent_findings": [alert_dict(alert) for alert in recent_findings],
            "mode": "simulated",
        })
    return {
        "agents": agent_rows,
        "count": len(agents),
        "total": total,
        "limit": limit,
        "offset": offset,
    }


@app.get("/api/endpoints")
def api_endpoints(
    db: Session = Depends(get_db),
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
):
    rows = db.scalars(select(Endpoint).order_by(Endpoint.id).limit(limit).offset(offset)).all()
    total = db.scalar(select(func.count()).select_from(Endpoint)) or 0
    result = []
    for endpoint in rows:
        event_count = db.scalar(select(func.count()).select_from(Event).where(Event.endpoint_id == endpoint.id)) or 0
        agent_types = db.scalars(select(Event.agent_type).where(Event.endpoint_id == endpoint.id).distinct()).all()
        result.append({
            "endpoint_id": endpoint.id, "id": endpoint.id, "hostname": endpoint.hostname,
            "platform": endpoint.platform, "status": endpoint.status, "last_seen": endpoint.last_seen,
            "event_count": event_count, "agent_types": agent_types, "mode": "simulated",
        })
    return {"endpoints": result, "count": len(result), "total": total, "limit": limit, "offset": offset}


@app.get("/api/endpoints/{endpoint_id}")
def api_endpoint_detail(endpoint_id: str, db: Session = Depends(get_db)):
    endpoint = db.get(Endpoint, endpoint_id)
    if endpoint is None:
        raise HTTPException(status_code=404, detail={"code": "not_found", "message": "Endpoint not found"})
    events = db.scalars(select(Event).where(Event.endpoint_id == endpoint_id)
                        .order_by(Event.timestamp.desc()).limit(50)).all()
    alerts = db.scalars(select(Alert).join(Event).where(Event.endpoint_id == endpoint_id)
                        .order_by(Alert.created_at.desc()).limit(50)).all()
    agent_types = db.scalars(select(Event.agent_type).where(Event.endpoint_id == endpoint_id).distinct()).all()
    return {
        "endpoint_id": endpoint.id, "id": endpoint.id, "hostname": endpoint.hostname,
        "platform": endpoint.platform, "status": endpoint.status, "last_seen": endpoint.last_seen,
        "event_count": db.scalar(select(func.count()).select_from(Event).where(Event.endpoint_id == endpoint_id)) or 0,
        "agent_types": agent_types, "events": [EventOut.model_validate(event) for event in events],
        "alerts": [alert_dict(alert) for alert in alerts], "mode": "simulated",
    }


@app.post("/api/agents/register", status_code=201)
def register_agent(body: AgentRegistration, db: Session = Depends(get_db)):
    if body.agent_type not in AGENT_TYPES:
        raise HTTPException(status_code=422, detail={"code": "invalid_agent_type", "message": "Unsupported simulated agent type"})
    agent = db.scalar(select(Agent).where(Agent.agent_type == body.agent_type))
    if agent is None:
        agent = Agent(
            id=body.agent_id or body.agent_type,
            agent_type=body.agent_type,
            description=body.description or AGENT_TYPES[body.agent_type],
        )
        db.add(agent)
    else:
        if body.agent_id:
            agent.id = body.agent_id
        agent.status = "active"
        agent.last_seen = datetime.now(timezone.utc)
        if body.description:
            agent.description = body.description
    if body.endpoint_id and db.get(Endpoint, body.endpoint_id) is None:
        db.add(Endpoint(id=body.endpoint_id))
    db.add(AuditLog(action="agent_registered", resource_id=agent.id,
                    details={"agent_type": body.agent_type, "simulated": True}))
    db.commit()
    db.refresh(agent)
    return {"agent_id": agent.id, "agent_type": agent.agent_type, "status": agent.status,
            "description": agent.description, "mode": "simulated"}


@app.get("/api/agents/{agent_id}")
def api_agent_detail(agent_id: str, db: Session = Depends(get_db)):
    agent = db.get(Agent, agent_id)
    if agent is None:
        agent = db.scalar(select(Agent).where(Agent.agent_type == agent_id))
    if agent is None:
        raise HTTPException(status_code=404, detail={"code": "not_found", "message": "Agent not found"})
    count = db.scalar(select(func.count()).select_from(Event).where(Event.agent_type == agent.agent_type)) or 0
    recent = db.scalars(select(Event).where(Event.agent_type == agent.agent_type)
                        .order_by(Event.timestamp.desc()).limit(10)).all()
    findings = db.scalars(
        select(Alert).join(Event).where(Event.agent_type == agent.agent_type)
        .order_by(Alert.created_at.desc()).limit(10)
    ).all()
    return {"agent_id": agent.id, "agent_type": agent.agent_type, "status": agent.status,
            "description": agent.description, "last_seen": agent.last_seen, "event_count": count,
            "events_processed": count, "recent_events": [EventOut.model_validate(event) for event in recent],
            "findings_count": db.scalar(
                select(func.count()).select_from(Alert).join(Event).where(Event.agent_type == agent.agent_type)
            ) or 0,
            "recent_findings": [alert_dict(alert) for alert in findings],
            "mode": "simulated"}


@app.get("/api/events")
def api_events(
    db: Session = Depends(get_db),
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    endpoint_id: str | None = None,
    agent_type: str | None = None,
    event_type: str | None = None,
    severity: str | None = None,
):
    stmt = select(Event).order_by(Event.timestamp.desc())
    count_stmt = select(func.count()).select_from(Event)
    filters = []
    if endpoint_id:
        filters.append(Event.endpoint_id == endpoint_id)
    if agent_type:
        filters.append(Event.agent_type == agent_type)
    if event_type:
        filters.append(Event.event_type == event_type)
    if severity:
        filters.append(Event.severity == severity)
    if filters:
        stmt = stmt.where(*filters)
        count_stmt = count_stmt.where(*filters)
    events = db.scalars(stmt.limit(limit).offset(offset)).all()
    event_rows = []
    for event in events:
        event_alerts = db.scalars(select(Alert).where(Alert.event_id == event.id)).all()
        findings = [{
            "finding_id": alert.id,
            "rule_name": alert.rule,
            "severity": alert.severity,
            "explanation": alert.description,
            "risk_score": alert.score,
        } for alert in event_alerts]
        event_data = EventOut.model_validate(event).model_dump(mode="json")
        detection = (event.payload or {}).get("_sentinelai", {})
        if event_alerts:
            severity_order = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
            event_data["severity"] = max(
                (alert.severity for alert in event_alerts),
                key=lambda value: severity_order.get(value, 0),
            )
        event_data["findings"] = detection.get("findings", findings)
        event_data["explanation"] = "; ".join(
            finding.get("explanation", "") for finding in event_data["findings"]
        )
        event_data["detection_method"] = "rules_and_compatible_models"
        event_data["risk_score"] = detection.get("risk_score", 0)
        event_data["model_score"] = detection.get("model_score")
        event_data["anomaly_score"] = detection.get("anomaly_score")
        event_data["model_version"] = detection.get("model_version")
        event_data["classifier_prediction"] = detection.get("classifier_prediction")
        event_data["anomaly_decision"] = detection.get("anomaly_decision")
        event_data["processing_time_ms"] = detection.get("processing_time_ms")
        event_rows.append(event_data)
    return {"events": event_rows,
            "count": len(events), "total": db.scalar(count_stmt) or 0, "limit": limit, "offset": offset}


@app.post("/api/events", status_code=201)
def api_ingest_event(body: EventCreate, db: Session = Depends(get_db)):
    event, alerts = process_event(db, body)
    return {"event": EventOut.model_validate(event), "alerts": [alert_dict(alert, event) for alert in alerts],
            "alert_count": len(alerts)}


@app.get("/api/events/{event_id}")
def api_event_detail(event_id: str, db: Session = Depends(get_db)):
    event = db.get(Event, event_id)
    if event is None:
        raise HTTPException(status_code=404, detail={"code": "not_found", "message": "Event not found"})
    alerts = db.scalars(select(Alert).where(Alert.event_id == event.id)).all()
    return {"event": EventOut.model_validate(event), "alerts": [alert_dict(alert, event) for alert in alerts]}


@app.post("/api/detect", status_code=201)
def api_detect(body: EventCreate, db: Session = Depends(get_db)):
    event, alerts = process_event(db, body)
    return {"event": EventOut.model_validate(event), "alerts": [alert_dict(alert, event) for alert in alerts],
            "alert_count": len(alerts), "detection_method": "rules_and_compatible_models"}


@app.get("/api/alerts")
def api_alerts(
    db: Session = Depends(get_db),
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    severity: str | None = None,
    status: str | None = None,
    endpoint_id: str | None = None,
):
    stmt = select(Alert).join(Event).order_by(Alert.created_at.desc())
    count_stmt = select(func.count()).select_from(Alert).join(Event)
    filters = []
    if severity:
        filters.append(Alert.severity == severity)
    if status:
        filters.append(Alert.status == status)
    if endpoint_id:
        filters.append(Event.endpoint_id == endpoint_id)
    if filters:
        stmt = stmt.where(*filters)
        count_stmt = count_stmt.where(*filters)
    alerts = db.scalars(stmt.limit(limit).offset(offset)).all()
    return {"alerts": [alert_dict(alert) for alert in alerts],
            "count": len(alerts), "total": db.scalar(count_stmt) or 0, "limit": limit, "offset": offset}


@app.get("/api/alerts/{alert_id}")
def api_alert_detail(alert_id: int, db: Session = Depends(get_db)):
    alert = db.get(Alert, alert_id)
    if alert is None:
        raise HTTPException(status_code=404, detail={"code": "not_found", "message": "Alert not found"})
    return {**alert_dict(alert), "event": EventOut.model_validate(alert.event)}


@app.patch("/api/alerts/{alert_id}")
def update_alert(alert_id: int, body: AlertUpdate, db: Session = Depends(get_db)):
    alert = db.get(Alert, alert_id)
    if alert is None:
        raise HTTPException(status_code=404, detail={"code": "not_found", "message": "Alert not found"})
    alert.status = body.status
    db.add(AuditLog(action="alert_status_updated", resource_id=str(alert_id), details={"status": body.status}))
    db.commit()
    db.refresh(alert)
    return alert_dict(alert)


@app.post("/api/simulations/run", status_code=201)
def api_run_simulation(body: SimulationRequest, db: Session = Depends(get_db)):
    expected_agent = {
        "normal_login": "login_agent", "brute_force_login": "login_agent",
        "normal_network": "network_agent", "dos_spike": "network_agent",
        "api_burst": "api_agent", "file_burst": "file_agent",
        "system_activity": "system_agent", "novel_combination": "correlation_agent",
    }[body.scenario]
    if body.agent_type != expected_agent:
        raise HTTPException(status_code=422, detail={
            "code": "agent_scenario_mismatch",
            "message": f"{body.scenario} requires {expected_agent}",
        })
    expected = "normal" if body.scenario in {"normal_login", "normal_network"} else "suspicious"
    endpoint_id = body.endpoint_id or f"SIMULATED-{uuid4().hex[:8].upper()}"
    simulation_id = str(uuid4())
    generated_agent, event_type, payload = _simulation_event(body.scenario, body.parameters)
    started = perf_counter()
    event_results = []
    event_objects = []
    all_alerts = []
    for index in range(body.event_count):
        if body.scenario == "novel_combination":
            generated_agent, event_type, payload = _novel_event(index)
        event_body = EventCreate(
            endpoint_id=endpoint_id,
            agent_type=generated_agent,
            event_type=event_type,
            source="simulation",
            scenario=body.scenario,
            severity="info" if expected == "normal" else "high",
            synthetic=True,
            payload=payload,
        )
        event, alerts = process_event(db, event_body, synthetic=True, commit=False)
        event_objects.append(event)
        event_results.append({"event_id": event.id, "alert_ids": [alert.id for alert in alerts]})
        all_alerts.extend(alert_dict(alert, event) for alert in alerts)
    duration_ms = (perf_counter() - started) * 1000
    max_severity = max(
        (alert["severity"] for alert in all_alerts),
        key=lambda value: {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}.get(value, 0),
        default=None,
    )
    actual = "normal" if not all_alerts else (
        "critical" if max_severity == "critical" else
        "high_risk" if max_severity == "high" else "suspicious"
    )
    if expected == "normal":
        evaluation = "expected_normal" if not all_alerts else "false_positive"
    else:
        evaluation = "detected" if all_alerts else "missed"
    detection_methods = sorted({
        "trained_classifier" if alert["rule"] == "trained_model" else
        "isolation_forest" if alert["rule"] == "isolation_forest_anomaly" else
        "cross_event_correlation" if alert["rule"] == "cross_agent_correlation" else
        "deterministic_rules"
        for alert in all_alerts
    })
    results = {
        "expected_outcome": expected,
        "actual_outcome": actual,
        "events_generated": len(event_results),
        "alerts_generated": len(all_alerts),
        "processing_duration_ms": round(duration_ms, 3),
        "detection_methods": detection_methods,
        "evaluation_result": evaluation,
        "events": event_results,
        "alerts": all_alerts,
        "synthetic_only": True,
    }
    simulation = Simulation(
        id=simulation_id, scenario=body.scenario, status="completed",
        event_count=len(event_results), alert_count=len(all_alerts), results=results,
    )
    db.add(simulation)
    db.flush()
    simulation.events.extend(event_objects)
    db.add(AuditLog(action="simulation_run", resource_id=simulation_id,
                    details={"scenario": body.scenario, "synthetic_only": True,
                             "event_count": len(event_results), "evaluation_result": evaluation}))
    db.commit()
    return {
        "id": simulation.id,
        "simulation_id": simulation.id,
        "scenario": simulation.scenario,
        "status": simulation.status,
        **results,
    }


@app.get("/api/simulations/history")
def api_simulation_history(db: Session = Depends(get_db), limit: int = Query(100, ge=1, le=500),
                           offset: int = Query(0, ge=0)):
    rows = db.scalars(select(Simulation).order_by(Simulation.created_at.desc()).limit(limit).offset(offset)).all()
    return {
        "simulations": [{
            "id": row.id, "simulation_id": row.id, "scenario": row.scenario, "status": row.status,
            "event_count": row.event_count, "events_generated": row.event_count, "alert_count": row.alert_count,
            "alerts_generated": row.alert_count, "created_at": row.created_at, **(row.results or {}),
        } for row in rows],
        "count": len(rows),
        "total": db.scalar(select(func.count()).select_from(Simulation)) or 0,
        "limit": limit,
        "offset": offset,
    }


@app.get("/api/simulations/{simulation_id}")
def api_simulation_detail(simulation_id: str, db: Session = Depends(get_db)):
    row = db.get(Simulation, simulation_id)
    if row is None:
        raise HTTPException(status_code=404, detail={"code": "not_found", "message": "Simulation not found"})
    return {"id": row.id, "simulation_id": row.id, "scenario": row.scenario,
            "status": row.status, "created_at": row.created_at,
            "event_count": row.event_count, "alert_count": row.alert_count, **(row.results or {})}


@app.get("/api/analytics/summary")
def api_analytics_summary(db: Session = Depends(get_db)):
    record_evaluation(db)
    report = evaluation_report()
    rf_test = ((report or {}).get("random_forest") or {}).get("test") or {}
    matrix = rf_test.get("confusion_matrix")
    false_positive_rate = None
    if matrix and len(matrix) >= 1 and len(matrix[0]) >= 2:
        negatives = matrix[0][0] + matrix[0][1]
        false_positive_rate = matrix[0][1] / negatives if negatives else None
    return {
        "dataset": "Synthetic supplied snapshot" if report else None,
        "evaluation_status": "available" if report else "unavailable",
        "metrics_available": bool(report),
        "precision": rf_test.get("precision"),
        "recall": rf_test.get("recall"),
        "f1_score": rf_test.get("f1"),
        "false_positive_rate": false_positive_rate,
        "evaluation_samples": (report or {}).get("split", {}).get("test"),
        "confusion_matrix": matrix,
        "synthetic_only": True,
        "warning": "Metrics from synthetic data do not establish real-world detection effectiveness.",
        "event_count": db.scalar(select(func.count()).select_from(Event)) or 0,
        "alert_count": db.scalar(select(func.count()).select_from(Alert)) or 0,
    }


@app.get("/api/analytics/confusion-matrix")
def api_confusion_matrix():
    report = evaluation_report()
    test_metrics = ((report or {}).get("random_forest") or {}).get("test") or {}
    return {"matrix": test_metrics.get("confusion_matrix"),
            "labels": ["normal", "threat"], "source": "synthetic held-out test split" if report else None}


@app.get("/api/analytics/attack-categories")
def api_attack_categories():
    report = evaluation_report()
    category_metrics = (report or {}).get("attack_categories", [])
    return {"categories": category_metrics, "source": "synthetic held-out test split" if report else None}


@app.get("/api/evaluations")
def api_evaluations(db: Session = Depends(get_db), limit: int = Query(50, ge=1, le=500),
                    offset: int = Query(0, ge=0)):
    record_evaluation(db)
    rows = db.scalars(select(Evaluation).order_by(Evaluation.created_at.desc()).limit(limit).offset(offset)).all()
    return {"evaluations": rows, "count": len(rows), "total": (
        db.scalar(select(func.count()).select_from(Evaluation)) or 0
    )}


@app.get("/api/models/status")
def api_model_status():
    status = model_status()
    models = {
        "random_forest": {
            "name": "Random Forest classifier",
            "available": status["available"],
            "threshold": status["threshold"],
        },
        "isolation_forest": {
            "name": "Isolation Forest anomaly detector",
            "available": status["isolation_forest_available"],
            "threshold": status["isolation_threshold"],
        },
    }
    return {"models": models, "available": status["available"],
            "message": status["message"], "error": status["error"], "synthetic_only": True}


@app.post("/api/feedback", status_code=201)
def api_feedback(body: FeedbackRequest, db: Session = Depends(get_db)):
    alert = db.get(Alert, body.alert_id)
    if alert is None:
        raise HTTPException(status_code=404, detail={"code": "not_found", "message": "Alert not found"})
    feedback = Feedback(alert_id=body.alert_id, verdict=body.verdict, notes=body.notes)
    db.add(feedback)
    if body.verdict in {"benign", "false_positive"}:
        alert.status = "false_positive"
    elif body.verdict in {"malicious", "true_positive"}:
        alert.status = "confirmed"
    db.add(AuditLog(action="analyst_feedback", resource_id=str(body.alert_id),
                    details={"verdict": body.verdict}))
    db.commit()
    db.refresh(feedback)
    return {"id": feedback.id, "alert_id": feedback.alert_id, "verdict": feedback.verdict,
            "notes": feedback.notes, "created_at": feedback.created_at}


@app.get("/api/settings")
def api_get_settings(db: Session = Depends(get_db)):
    return {"settings": get_detection_settings(db), "updated_at": (
        db.get(AppSetting, "detection_thresholds").updated_at
        if db.get(AppSetting, "detection_thresholds") else None
    )}


@app.patch("/api/settings")
def api_update_settings(body: SettingsUpdate, db: Session = Depends(get_db)):
    changes = {key: value for key, value in body.model_dump(exclude_unset=True).items() if value is not None}
    if not changes:
        raise HTTPException(status_code=422, detail={"code": "empty_settings", "message": "Provide at least one setting to update"})
    settings = get_detection_settings(db)
    settings.update(changes)
    row = db.get(AppSetting, "detection_thresholds")
    if row is None:
        row = AppSetting(key="detection_thresholds", value=settings)
        db.add(row)
    else:
        row.value = settings
    db.add(AuditLog(action="settings_updated", resource_id="detection_thresholds",
                    details={"updated_keys": sorted(changes)}))
    db.commit()
    db.refresh(row)
    return {"settings": settings, "updated_at": row.updated_at}
