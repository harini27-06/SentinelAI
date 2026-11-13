from time import perf_counter

from app.services.detection import AGENT_TYPES, detect, model_status


class BaseAgent:
    agent_type = ""
    supported_event_types = frozenset({"telemetry"})
    supported_rules = frozenset()

    @property
    def agent_id(self):
        return f"simulated-{self.agent_type}"

    def supports(self, event_type):
        return event_type in self.supported_event_types

    def analyze(self, event, thresholds=None):
        started = perf_counter()
        if event.agent_type != self.agent_type or not self.supports(event.event_type):
            return {
                "agent_id": self.agent_id,
                "agent_type": self.agent_type,
                "status": "rejected",
                "accepted": False,
                "processing_time_ms": (perf_counter() - started) * 1000,
                "findings": [],
                "error": f"Unsupported {self.agent_type} event type: {event.event_type}",
            }
        matches, model_score, anomaly_score = detect(event, thresholds)
        matches = [match for match in matches if match["rule"] in self.supported_rules]
        status = model_status()
        findings = [
            {
                "finding_id": match["rule"],
                "agent_id": self.agent_id,
                "agent_type": self.agent_type,
                "rule": match["rule"],
                "severity": match["severity"],
                "explanation": match["description"],
                "score": match.get("score", model_score),
                "detection_method": (
                    "trained_classifier" if match["rule"] == "trained_model" else
                    "isolation_forest" if match["rule"] == "isolation_forest_anomaly" else
                    "deterministic_rule"
                ),
            }
            for match in matches
        ]
        return {
            "agent_id": self.agent_id,
            "agent_type": self.agent_type,
            "status": "active",
            "accepted": True,
            "processing_time_ms": (perf_counter() - started) * 1000,
            "findings": findings,
            "matches": matches,
            "model_score": model_score,
            "anomaly_score": anomaly_score,
            "model_version": status["model"],
            "classifier_prediction": (
                "threat_like" if model_score is not None and model_score >= float(status["threshold"])
                else "normal_like" if model_score is not None else None
            ),
            "anomaly_decision": (
                "anomalous" if anomaly_score is not None and
                anomaly_score >= float(status["isolation_threshold"])
                else "within_reference" if anomaly_score is not None else None
            ),
        }


class LoginAgent(BaseAgent):
    agent_type = "login_agent"
    supported_event_types = frozenset({
        "telemetry", "login_success", "login_failure_burst", "authentication", "authentication_anomaly",
    })
    supported_rules = frozenset({
        "repeated_login_failures", "suspicious_login_frequency", "authentication_anomaly",
    })


class NetworkAgent(BaseAgent):
    agent_type = "network_agent"
    supported_event_types = frozenset({"telemetry", "network_flow"})
    supported_rules = frozenset({
        "network_scan", "dos_like_traffic_spike", "trained_model", "isolation_forest_anomaly",
    })


class FileActivityAgent(BaseAgent):
    agent_type = "file_agent"
    supported_event_types = frozenset({"telemetry", "file_integrity", "file_activity"})
    supported_rules = frozenset({"file_tampering", "suspicious_file_access"})


class ApiSecurityAgent(BaseAgent):
    agent_type = "api_agent"
    supported_event_types = frozenset({"telemetry", "api_request", "api_security"})
    supported_rules = frozenset({"api_abuse", "repeated_unauthorized_requests"})


class SystemActivityAgent(BaseAgent):
    agent_type = "system_agent"
    supported_event_types = frozenset({"telemetry", "system_metrics", "system_activity"})
    supported_rules = frozenset({"system_anomaly"})


class CorrelationAgent(BaseAgent):
    agent_type = "correlation_agent"
    supported_event_types = frozenset({"telemetry", "correlated_risk_signals"})
    supported_rules = frozenset({"correlated_signals"})


AGENT_INSTANCES = {
    agent.agent_type: agent
    for agent in (LoginAgent(), NetworkAgent(), FileActivityAgent(), ApiSecurityAgent(),
                  SystemActivityAgent(), CorrelationAgent())
}


def get_agent(agent_type):
    return AGENT_INSTANCES.get(agent_type)


def list_agents():
    return [{
        "agent_id": agent.agent_id,
        "agent_type": agent.agent_type,
        "status": "active",
        "description": AGENT_TYPES[agent.agent_type],
        "simulated": True,
    } for agent in AGENT_INSTANCES.values()]


def event_agent_type(scenario):
    return {
        "login_attack": "login_agent",
        "network_scan": "network_agent",
        "file_tampering": "file_agent",
        "api_abuse": "api_agent",
        "system_anomaly": "system_agent",
        "correlated_activity": "correlation_agent",
    }[scenario]
