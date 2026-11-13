import logging
import pickle
from functools import lru_cache
from pathlib import Path

import joblib
import pandas as pd

from app.config import MODEL_PATH

logger = logging.getLogger(__name__)
_MODEL_LOAD_ERROR = None
DEFAULT_THRESHOLDS = {
    "failed_login_threshold": 5,
    "login_frequency_threshold": 15,
    "unauthorized_request_threshold": 5,
    "api_requests_per_minute": 300,
    "file_modifications": 20,
    "network_unique_ports": 15,
    "dos_rate_threshold": 1000,
    "system_resource_threshold": 95,
}

AGENT_TYPES = {
    "login_agent": "Detects simulated authentication anomalies.",
    "network_agent": "Detects unusual network-flow patterns.",
    "file_agent": "Detects simulated file-integrity events.",
    "api_agent": "Detects simulated API-abuse patterns.",
    "system_agent": "Detects simulated system resource anomalies.",
    "correlation_agent": "Correlates multiple behavior indicators.",
}

RULES = (
    ("repeated_login_failures", "high", "Repeated failed logins",
     lambda p, t: _number(p, "failed_logins") >= t["failed_login_threshold"]),
    ("suspicious_login_frequency", "high", "Unusually frequent authentication activity",
     lambda p, t: _number(p, "login_frequency") >= t["login_frequency_threshold"]),
    ("authentication_anomaly", "medium", "Synthetic authentication anomaly indicator",
     lambda p, t: p.get("authentication_anomaly") is True),
    ("network_scan", "high", "Possible network scanning behavior",
     lambda p, t: _number(p, "unique_ports") >= t["network_unique_ports"] or p.get("scenario") == "network_scan"),
    ("dos_like_traffic_spike", "high", "Unusually high synthetic network traffic rate",
     lambda p, t: _number(p, "rate") >= t["dos_rate_threshold"] or p.get("scenario") == "dos_spike"),
    ("file_tampering", "critical", "File integrity or ransomware-like behavior",
     lambda p, t: _number(p, "file_changes") >= t["file_modifications"] or p.get("scenario") == "file_tampering"),
    ("suspicious_file_access", "high", "Unexpected synthetic file-access pattern",
     lambda p, t: p.get("suspicious_access") is True or p.get("access_pattern") == "unexpected"),
    ("api_abuse", "high", "Excessive API request rate",
     lambda p, t: _number(p, "requests_per_minute") >= t["api_requests_per_minute"] or p.get("scenario") == "api_abuse"),
    ("repeated_unauthorized_requests", "high", "Repeated unauthorized API requests",
     lambda p, t: _number(p, "unauthorized_requests") >= t["unauthorized_request_threshold"]),
    ("system_anomaly", "medium", "Unusual system resource usage",
     lambda p, t: _number(p, "cpu_percent") >= t["system_resource_threshold"] or
                  _number(p, "memory_percent") >= t["system_resource_threshold"] or
                  p.get("scenario") == "system_anomaly"),
)


def _number(payload, key):
    try:
        return float(payload.get(key, 0))
    except (ValueError, TypeError):
        return 0.0


@lru_cache(maxsize=4)
def _load_artifact(path, modified_ns, size):
    try:
        return joblib.load(path), None
    except (OSError, EOFError, ValueError, ImportError, AttributeError, TypeError, pickle.UnpicklingError) as error:
        message = f"{type(error).__name__}: {error}"
        logger.exception("Could not load the SentinelAI model artifact")
        return None, message


def _load_model():
    global _MODEL_LOAD_ERROR
    _MODEL_LOAD_ERROR = None
    path = Path(MODEL_PATH)
    try:
        file_stat = path.stat()
    except FileNotFoundError:
        return None
    except OSError as error:
        _MODEL_LOAD_ERROR = f"{type(error).__name__}: {error}"
        logger.exception("Could not access the SentinelAI model artifact")
        return None
    model, _MODEL_LOAD_ERROR = _load_artifact(str(path), file_stat.st_mtime_ns, file_stat.st_size)
    return model


def detect(event, thresholds=None):
    thresholds = {**DEFAULT_THRESHOLDS, **(thresholds or {})}
    payload = dict(event.payload or {})
    payload.setdefault("scenario", event.scenario)
    if event.label is not None:
        payload.setdefault("label", event.label)
    matches = [
        {"rule": name, "severity": severity, "description": description}
        for name, severity, description, predicate in RULES
        if predicate(payload, thresholds)
    ]
    indicators = payload.get("indicators", [])
    if event.agent_type == "correlation_agent" and isinstance(indicators, list) and len({str(item) for item in indicators}) >= 2:
        matches.append({"rule": "correlated_signals", "severity": "high",
                        "description": "Correlation agent observed multiple related risk indicators"})
    score = None
    anomaly_score = None
    if event.agent_type == "network_agent" and event.event_type == "network_flow":
        model_data = _load_model()
    else:
        model_data = None
    if model_data:
        try:
            features = model_data["features"]
            if not all(feature in payload for feature in features):
                return matches, score, anomaly_score
            values = {key: payload.get(key) for key in features}
            sample = pd.DataFrame([values])
            score = float(model_data["pipeline"].predict_proba(sample)[0][1])
            if score >= float(model_data.get("threshold", 0.5)):
                matches.append({"rule": "trained_model", "severity": "medium",
                                "description": "Trained classifier anomaly score exceeded threshold", "score": score})
            isolation = model_data.get("isolation_forest")
            if isolation is not None:
                anomaly_score = -float(isolation.decision_function(sample)[0])
                if anomaly_score >= float(model_data.get("isolation_threshold", float("inf"))):
                    matches.append({
                        "rule": "isolation_forest_anomaly",
                        "severity": "medium",
                        "description": "Isolation Forest anomaly score exceeded its validation-tuned threshold",
                        "score": anomaly_score,
                    })
        except (ValueError, TypeError, KeyError, AttributeError) as error:
            logger.warning("Model inference skipped for event %s: %s", event.id, error)
    return matches, score, anomaly_score


def model_status():
    model = _load_model()
    available = model is not None
    return {
        "available": available,
        "path": str(MODEL_PATH),
        "model": model.get("name") if model else None,
        "threshold": model.get("threshold") if model else None,
        "isolation_forest_available": bool(model and model.get("isolation_forest")),
        "isolation_threshold": model.get("isolation_threshold") if model else None,
        "error": _MODEL_LOAD_ERROR,
        "message": (
            "Trained Random Forest and Isolation Forest artifacts loaded."
            if available else "Model artifacts unavailable; deterministic rules remain available."
        ),
    }
