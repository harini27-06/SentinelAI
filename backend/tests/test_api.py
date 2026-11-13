from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
from fastapi.testclient import TestClient

from app.database import Base, get_db
import app.services.detection as detection
import app.main as main
from app.main import app


test_engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
TestSession = sessionmaker(bind=test_engine, autoflush=False, expire_on_commit=False)


def override_db():
    db = TestSession()
    try:
        yield db
    finally:
        db.close()


def setup_module():
    Base.metadata.create_all(test_engine)
    main.engine = test_engine
    app.dependency_overrides[get_db] = override_db


def setup_function():
    Base.metadata.drop_all(test_engine)
    Base.metadata.create_all(test_engine)
    main.engine = test_engine


def teardown_module():
    app.dependency_overrides.clear()
    Base.metadata.drop_all(test_engine)


def test_health_agents_and_model_missing_resilience():
    with TestClient(app) as client:
        assert client.get("/health").json()["status"] == "ok"
        agents = client.get("/api/v1/agents").json()["agents"]
        assert {agent["agent_type"] for agent in agents} >= {
            "login_agent", "network_agent", "file_agent", "api_agent", "system_agent", "correlation_agent"
        }
        assert "available" in client.get("/api/v1/model/status").json()


def test_ingestion_rules_analytics_feedback_and_errors():
    with TestClient(app) as client:
        response = client.post("/api/v1/events", json={
            "id": "test-login-event", "endpoint_id": "test-endpoint", "agent_type": "login_agent",
            "event_type": "login_failure_burst", "payload": {"failed_logins": 8},
        })
        assert response.status_code == 201
        assert "repeated_login_failures" in {alert["rule"] for alert in response.json()["alerts"]}
        alert_id = response.json()["alerts"][0]["id"]
        feedback = client.post(f"/api/v1/alerts/{alert_id}/feedback",
                               json={"verdict": "false_positive", "notes": "test"})
        assert feedback.status_code == 201
        assert client.get("/api/v1/alerts").json()["alerts"][0]["status"] == "false_positive"
        assert client.get("/api/v1/analytics").json()["events"] == 1
        assert client.post("/api/v1/events", json={"endpoint_id": "x"}).status_code == 422
        invalid = client.post("/api/v1/events", json={
            "endpoint_id": "x", "agent_type": "login_agent", "severity": "urgent",
        })
        assert invalid.status_code == 422
        assert invalid.json()["error"]["code"] == "validation_error"
        assert client.post("/api/v1/alerts/999/feedback", json={"verdict": "benign"}).status_code == 404


def test_simulation_uses_synthetic_pipeline():
    with TestClient(app) as client:
        response = client.post("/api/v1/simulations", json={
            "scenario": "network_scan", "endpoint_id": "synthetic-only", "count": 2,
        })
        assert response.status_code == 201
        assert response.json()["event_count"] == 2
        assert response.json()["alert_count"] == 2
        events = client.get("/api/v1/events", params={"endpoint_id": "synthetic-only"}).json()["events"]
        assert len(events) == 2
        assert all(event["synthetic"] and event["source"] == "simulation" for event in events)
        correlated = client.post("/api/v1/simulations", json={
            "scenario": "correlated_activity", "endpoint_id": "synthetic-correlation",
        })
        assert correlated.status_code == 201
        assert correlated.json()["alert_count"] == 1


def test_required_api_routes_and_end_to_end_simulation_outcomes():
    with TestClient(app) as client:
        assert client.get("/api/health").json()["status"] == "ok"
        assert "events_processed" in client.get("/api/dashboard/stats").json()
        assert client.get("/api/agents").json()["count"] >= 6
        registered = client.post("/api/agents/register", json={
            "agent_type": "network_agent", "endpoint_id": "registered-endpoint",
        })
        assert registered.status_code == 201
        assert client.get("/api/agents/network_agent").status_code == 200
        assert client.get("/api/endpoints/registered-endpoint").status_code == 200
        assert isinstance(client.get("/api/models/status").json()["models"]["random_forest"]["available"], bool)

        normal = client.post("/api/simulations/run", json={
            "scenario": "normal_login", "agent_type": "login_agent", "event_count": 2,
        })
        assert normal.status_code == 201, normal.text
        assert normal.json()["expected_outcome"] == "normal"
        assert normal.json()["actual_outcome"] == "normal"
        assert normal.json()["alerts_generated"] == 0
        assert normal.json()["evaluation_result"] == "expected_normal"

        suspicious = client.post("/api/simulations/run", json={
            "scenario": "brute_force_login", "agent_type": "login_agent", "event_count": 2,
            "parameters": {"failure_count": 10},
        })
        assert suspicious.status_code == 201, suspicious.text
        assert suspicious.json()["actual_outcome"] in {"high_risk", "critical", "suspicious"}
        assert suspicious.json()["alerts_generated"] > 0
        assert suspicious.json()["evaluation_result"] == "detected"
        history = client.get("/api/simulations/history?limit=1&offset=1").json()
        assert history["count"] == 1
        assert history["total"] == 2
        assert history["limit"] == 1
        assert history["offset"] == 1

        novel = client.post("/api/simulations/run", json={
            "scenario": "novel_combination", "agent_type": "correlation_agent", "event_count": 3,
        })
        assert novel.status_code == 201, novel.text
        assert novel.json()["alerts_generated"] > 0
        assert "cross_agent_correlation" in {alert["rule"] for alert in novel.json()["alerts"]}
        assert "cross_event_correlation" in novel.json()["detection_methods"]

        alert_id = suspicious.json()["alerts"][0]["id"]
        updated = client.patch(f"/api/alerts/{alert_id}", json={"status": "investigating"})
        assert updated.status_code == 200
        assert updated.json()["status"] == "investigating"
        assert client.get(f"/api/alerts/{alert_id}").status_code == 200
        assert client.post("/api/feedback", json={
            "alert_id": alert_id, "verdict": "false_positive", "notes": "synthetic test feedback",
        }).status_code == 201
        assert client.get("/api/analytics/summary").status_code == 200
        assert client.get("/api/analytics/confusion-matrix").status_code == 200
        assert client.get("/api/analytics/attack-categories").status_code == 200
        assert client.get("/api/events?limit=2&offset=0").status_code == 200


def test_missing_model_artifact_keeps_rules_available(monkeypatch, tmp_path):
    monkeypatch.setattr(detection, "MODEL_PATH", tmp_path / "does-not-exist.joblib")
    with TestClient(app) as client:
        status = client.get("/api/models/status").json()
        assert status["models"]["random_forest"]["available"] is False
        response = client.post("/api/events", json={
            "endpoint_id": "no-model-endpoint", "agent_type": "login_agent",
            "event_type": "login_failure_burst", "payload": {"failed_logins": 8},
        })
        assert response.status_code == 201
        assert "repeated_login_failures" in {alert["rule"] for alert in response.json()["alerts"]}


def test_persisted_settings_change_detection_thresholds():
    with TestClient(app) as client:
        updated = client.patch("/api/settings", json={"failed_login_threshold": 7})
        assert updated.status_code == 200
        assert client.get("/api/settings").json()["settings"]["failed_login_threshold"] == 7
        below_threshold = client.post("/api/events", json={
            "id": "below-setting-threshold", "endpoint_id": "settings-endpoint",
            "agent_type": "login_agent", "event_type": "login_failure_burst",
            "payload": {"failed_logins": 6},
        })
        at_threshold = client.post("/api/events", json={
            "id": "at-setting-threshold", "endpoint_id": "settings-endpoint",
            "agent_type": "login_agent", "event_type": "login_failure_burst",
            "payload": {"failed_logins": 7},
        })
        assert below_threshold.json()["alert_count"] == 0
        assert "repeated_login_failures" in {
            alert["rule"] for alert in at_threshold.json()["alerts"]
        }


def test_agent_scopes_reject_cross_type_events_without_running_flow_models():
    with TestClient(app) as client:
        rejected = client.post("/api/events", json={
            "endpoint_id": "scope-endpoint", "agent_type": "login_agent",
            "event_type": "network_flow", "payload": {"rate": 1000000},
        })
        assert rejected.status_code == 422
        unrelated = client.post("/api/events", json={
            "endpoint_id": "scope-endpoint", "agent_type": "system_agent",
            "event_type": "system_metrics", "payload": {"rate": 1000000, "cpu_percent": 20},
        })
        assert unrelated.status_code == 201
        metadata = unrelated.json()["event"]["payload"]["_sentinelai"]
        assert metadata["model_score"] is None
        assert unrelated.json()["alert_count"] == 0, [
            alert["rule"] for alert in unrelated.json()["alerts"]
        ]


def test_sensitive_payload_and_labels_are_not_persisted_as_detection_signals():
    with TestClient(app) as client:
        rejected = client.post("/api/events", json={
            "endpoint_id": "safe-payload-endpoint", "agent_type": "login_agent",
            "event_type": "authentication", "payload": {"password": "do-not-echo-this"},
        })
        assert rejected.status_code == 422
        assert "do-not-echo-this" not in rejected.text
        labeled = client.post("/api/events", json={
            "endpoint_id": "safe-payload-endpoint", "agent_type": "network_agent",
            "event_type": "network_flow", "label": 1, "payload": {"rate": 25},
        })
        assert labeled.status_code == 201
        assert labeled.json()["alert_count"] == 0


def test_synthetic_scenarios_execute_rules_and_report_normal_false_positives():
    scenarios = [
        ("dos_spike", "network_agent", {}, True),
        ("api_burst", "api_agent", {"request_rate": 500}, True),
        ("file_burst", "file_agent", {"modification_count": 25}, True),
        ("system_activity", "system_agent", {}, True),
        ("normal_network", "network_agent", {}, False),
    ]
    with TestClient(app) as client:
        for scenario, agent_type, parameters, should_detect in scenarios:
            response = client.post("/api/simulations/run", json={
                "scenario": scenario, "agent_type": agent_type, "event_count": 1,
                "parameters": parameters,
            })
            assert response.status_code == 201, response.text
            result = response.json()
            assert result["events_generated"] == 1
            assert result["expected_outcome"] == ("suspicious" if should_detect else "normal")
            if should_detect:
                assert result["alerts_generated"] > 0
                assert result["evaluation_result"] == "detected"
            else:
                assert result["evaluation_result"] in {"expected_normal", "false_positive"}
                assert result["actual_outcome"] == ("normal" if not result["alerts_generated"] else "suspicious")
