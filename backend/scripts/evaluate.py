import argparse
import json
import time
from pathlib import Path

import joblib

from scripts.train import (
    DEFAULT_ARTIFACT, DEFAULT_INPUT, attack_category_metrics, held_out_metrics,
    metrics_at_threshold, split_data,
)


def evaluate(input_path=DEFAULT_INPUT, artifact_path=DEFAULT_ARTIFACT):
    data = split_data(input_path)
    test_x, test_y = data["test_x"], data["test_y"]
    artifact = joblib.load(artifact_path)
    started = time.perf_counter()
    rf_scores = artifact["pipeline"].predict_proba(test_x)[:, 1]
    rf_test = metrics_at_threshold(test_y, rf_scores, artifact["threshold"])
    rf_test["detection_latency_ms_per_event"] = (time.perf_counter() - started) * 1000 / len(test_x)
    started = time.perf_counter()
    isolation_scores = -artifact["isolation_forest"].decision_function(test_x)
    isolation_test = metrics_at_threshold(test_y, isolation_scores, artifact["isolation_threshold"])
    isolation_test["detection_latency_ms_per_event"] = (time.perf_counter() - started) * 1000 / len(test_x)
    return {"model": artifact["name"], "dataset": artifact.get("dataset"),
            "test_rows": len(test_y), "validation_rows": len(data["val_y"]),
            "held_out_synthetic_rows": len(data["held_out_y"]),
            "random_forest": rf_test,
            "isolation_forest_normal_only_fit": isolation_test,
            "attack_categories": attack_category_metrics(
                test_y, rf_scores, artifact["threshold"], data["test_categories"]),
            "held_out_synthetic_pattern": held_out_metrics(
                artifact["pipeline"], artifact["threshold"], data["held_out_x"], data["held_out_y"]),
            "isolation_forest_held_out_synthetic_pattern": held_out_metrics(
                artifact["isolation_forest"], artifact["isolation_threshold"],
                data["held_out_x"], data["held_out_y"], anomaly=True),
            "warning": "Evaluation uses synthetic data only; no real-world efficacy is established."}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Evaluate the trained model on its stratified synthetic holdout.")
    parser.add_argument("--input", type=Path, default=DEFAULT_INPUT)
    parser.add_argument("--artifact", type=Path, default=DEFAULT_ARTIFACT)
    args = parser.parse_args()
    print(json.dumps(evaluate(args.input, args.artifact), indent=2))
