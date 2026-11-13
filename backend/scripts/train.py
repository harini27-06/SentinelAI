import argparse
import json
import time
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.compose import ColumnTransformer
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.impute import SimpleImputer
from sklearn.metrics import (accuracy_score, classification_report, confusion_matrix,
                             f1_score, precision_score, recall_score, roc_auc_score)
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder, StandardScaler

from scripts.preprocess import DEFAULT_INPUT, LEAKAGE_COLUMNS

BASE_DIR = Path(__file__).resolve().parents[1]
DEFAULT_ARTIFACT = BASE_DIR / "artifacts" / "detection_model.joblib"
DEFAULT_METRICS = BASE_DIR / "artifacts" / "training_metrics.json"
HELD_OUT_SCENARIOS = {"unseen_pattern_simulation"}
HELD_OUT_CATEGORIES = {"novel_anomaly"}


def metrics_at_threshold(y_true, scores, threshold):
    predicted = (scores >= threshold).astype(int)
    matrix = confusion_matrix(y_true, predicted, labels=[0, 1])
    tn, fp, fn, tp = matrix.ravel()
    return {
        "threshold": float(threshold),
        "precision": float(precision_score(y_true, predicted, zero_division=0)),
        "recall": float(recall_score(y_true, predicted, zero_division=0)),
        "f1": float(f1_score(y_true, predicted, zero_division=0)),
        "accuracy": float(accuracy_score(y_true, predicted)),
        "false_positive_rate": float(fp / (tn + fp)) if tn + fp else None,
        "roc_auc": float(roc_auc_score(y_true, scores)) if len(set(y_true)) == 2 else None,
        "confusion_matrix": matrix.tolist(),
    }


def tune_threshold(y_true, scores, max_false_positive_rate=None):
    candidates = np.unique(np.concatenate(([0.0, 1.0], np.quantile(scores, np.linspace(0, 1, 201)))))
    results = [metrics_at_threshold(y_true, scores, threshold) for threshold in candidates]
    if max_false_positive_rate is not None:
        eligible = [
            metric for metric in results
            if metric["false_positive_rate"] is not None
            and metric["false_positive_rate"] <= max_false_positive_rate
        ]
        if eligible:
            results = eligible
        else:
            return min(
                results,
                key=lambda metric: (
                    float("inf") if metric["false_positive_rate"] is None else metric["false_positive_rate"],
                    -metric["recall"],
                ),
            )
    return max(results, key=lambda metric: (metric["f1"], metric["precision"], metric["threshold"]))


def prepare_data(input_path):
    frame = pd.read_csv(input_path)
    if "label" not in frame:
        raise ValueError("Dataset is missing required label column")
    y = pd.to_numeric(frame.pop("label"), errors="raise").astype(int).to_numpy()
    if not set(np.unique(y)).issubset({0, 1}):
        raise ValueError("Only binary 0/1 labels are supported")
    excluded = [column for column in frame.columns if column.lower() in LEAKAGE_COLUMNS]
    frame = frame.drop(columns=excluded)
    if frame.shape[1] == 0:
        raise ValueError("No eligible model features remain after leakage exclusions")
    return frame, y, sorted(excluded)


def split_data(input_path):
    features, labels, excluded = prepare_data(input_path)
    raw = pd.read_csv(input_path)
    scenarios = raw["scenario"].fillna("").astype(str).str.lower() if "scenario" in raw else pd.Series("", index=raw.index)
    categories = raw["attack_cat"].fillna("Uncategorized").astype(str) if "attack_cat" in raw else pd.Series("Uncategorized", index=raw.index)
    held_out = scenarios.isin(HELD_OUT_SCENARIOS) | categories.str.lower().isin(HELD_OUT_CATEGORIES)

    known_x = features.loc[~held_out]
    known_y = labels[~held_out.to_numpy()]
    held_out_x = features.loc[held_out]
    held_out_y = labels[held_out.to_numpy()]
    if len(known_x) < 10 or len(np.unique(known_y)) != 2:
        raise ValueError("Need at least ten known-pattern rows with both label classes")

    train_val_x, test_x, train_val_y, test_y = train_test_split(
        known_x, known_y, test_size=0.2, random_state=42, stratify=known_y)
    train_x, val_x, train_y, val_y = train_test_split(
        train_val_x, train_val_y, test_size=0.25, random_state=42, stratify=train_val_y)
    return {
        "train_x": train_x, "train_y": train_y,
        "val_x": val_x, "val_y": val_y,
        "test_x": test_x, "test_y": test_y,
        "test_categories": categories.loc[test_x.index].to_numpy(),
        "held_out_x": held_out_x, "held_out_y": held_out_y,
        "excluded": excluded,
        "label_distribution": {str(int(label)): int(count) for label, count in pd.Series(labels).value_counts().items()},
    }


def build_preprocessor(frame, scale_numeric=False):
    numeric = frame.select_dtypes(include=["number", "bool"]).columns.tolist()
    categorical = [column for column in frame.columns if column not in numeric]
    numeric_steps = [("imputer", SimpleImputer(strategy="median"))]
    if scale_numeric:
        numeric_steps.append(("scaler", StandardScaler()))
    transformers = []
    if numeric:
        transformers.append(("numeric", Pipeline(numeric_steps), numeric))
    if categorical:
        transformers.append(("categorical", Pipeline([
            ("imputer", SimpleImputer(strategy="most_frequent")),
            ("onehot", OneHotEncoder(handle_unknown="ignore")),
        ]), categorical))
    return ColumnTransformer(transformers, remainder="drop")


def attack_category_metrics(y_true, scores, threshold, categories):
    predicted = (scores >= threshold).astype(int)
    result = []
    for category in sorted(set(categories)):
        if str(category).strip().lower() == "normal":
            continue
        mask = categories == category
        values = metrics_at_threshold(y_true[mask], scores[mask], threshold)
        result.append({
            "category": str(category),
            "precision": values["precision"],
            "recall": values["recall"],
            "f1_score": values["f1"],
            "support": int(mask.sum()),
            "detected": int(predicted[mask].sum()),
        })
    return result


def held_out_metrics(pipeline, threshold, x, y, anomaly=False):
    if len(x) == 0:
        return {"available": False, "records": 0, "note": "No held-out synthetic scenario rows were present."}
    scores = -pipeline.decision_function(x) if anomaly else pipeline.predict_proba(x)[:, 1]
    predictions = (scores >= threshold).astype(int)
    positive = int((y == 1).sum())
    return {
        "available": True,
        "scenario": "unseen_pattern_simulation",
        "category": "Novel_Anomaly",
        "records": int(len(y)),
        "detections": int(((predictions == 1) & (y == 1)).sum()),
        "threat_recall": float(recall_score(y, predictions, zero_division=0)),
        "threat_records": positive,
        "false_positive_rate": None,
        "score_type": "uncalibrated anomaly score" if anomaly else "classifier probability",
        "note": "Held-out synthetic pattern rows were excluded from training and validation. This is not evidence of real-world zero-day detection.",
    }


def train(input_path=DEFAULT_INPUT, artifact_path=DEFAULT_ARTIFACT, metrics_path=DEFAULT_METRICS):
    data = split_data(input_path)
    train_x, train_y = data["train_x"], data["train_y"]
    val_x, val_y = data["val_x"], data["val_y"]
    test_x, test_y = data["test_x"], data["test_y"]
    rf_pipeline = Pipeline([
        ("preprocess", build_preprocessor(train_x)),
        ("classifier", RandomForestClassifier(n_estimators=250, class_weight="balanced",
                                              random_state=42, n_jobs=-1, min_samples_leaf=2)),
    ])
    rf_pipeline.fit(train_x, train_y)
    val_scores = rf_pipeline.predict_proba(val_x)[:, 1]
    rf_threshold_metrics = tune_threshold(val_y, val_scores)
    started = time.perf_counter()
    test_scores = rf_pipeline.predict_proba(test_x)[:, 1]
    rf_latency = (time.perf_counter() - started) * 1000 / len(test_x)
    rf_test = metrics_at_threshold(test_y, test_scores, rf_threshold_metrics["threshold"])
    rf_test["detection_latency_ms_per_event"] = rf_latency
    rf_test["classification_report"] = classification_report(
        test_y, (test_scores >= rf_threshold_metrics["threshold"]).astype(int),
        labels=[0, 1], output_dict=True, zero_division=0)

    normal_train = train_x.loc[train_y == 0]
    isolation_pipeline = Pipeline([
        ("preprocess", build_preprocessor(normal_train, scale_numeric=True)),
        ("detector", IsolationForest(n_estimators=250, contamination="auto", random_state=42, n_jobs=-1)),
    ])
    isolation_pipeline.fit(normal_train)
    val_anomaly_scores = -isolation_pipeline.decision_function(val_x)
    isolation_threshold_metrics = tune_threshold(
        val_y, val_anomaly_scores, max_false_positive_rate=0.05)
    started = time.perf_counter()
    test_anomaly_scores = -isolation_pipeline.decision_function(test_x)
    isolation_latency = (time.perf_counter() - started) * 1000 / len(test_x)
    isolation_test = metrics_at_threshold(test_y, test_anomaly_scores, isolation_threshold_metrics["threshold"])
    isolation_test["detection_latency_ms_per_event"] = isolation_latency

    artifact_path = Path(artifact_path)
    artifact_path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump({
        "name": "RandomForestClassifier",
        "pipeline": rf_pipeline,
        "features": train_x.columns.tolist(),
        "threshold": rf_threshold_metrics["threshold"],
        "isolation_forest": isolation_pipeline,
        "isolation_threshold": isolation_threshold_metrics["threshold"],
        "dataset": "synthetic_supplied_snapshot",
        "excluded_leakage_columns": data["excluded"],
        "held_out_scenarios": sorted(HELD_OUT_SCENARIOS | HELD_OUT_CATEGORIES),
    }, artifact_path)
    metrics = {
        "dataset": "synthetic_supplied_snapshot",
        "rows": len(train_x) + len(val_x) + len(test_x) + len(data["held_out_y"]),
        "label_distribution": data["label_distribution"],
        "split": {
            "train": len(train_y), "validation": len(val_y), "test": len(test_y),
            "held_out_synthetic": len(data["held_out_y"]),
        },
        "feature_columns": train_x.columns.tolist(),
        "excluded_leakage_columns": data["excluded"],
        "random_forest": {
            "validation": rf_threshold_metrics,
            "test": rf_test,
            "held_out_synthetic_pattern": held_out_metrics(
                rf_pipeline, rf_threshold_metrics["threshold"], data["held_out_x"], data["held_out_y"]),
        },
        "isolation_forest_normal_only_fit": {
            "validation": isolation_threshold_metrics,
            "test": isolation_test,
            "held_out_synthetic_pattern": held_out_metrics(
                isolation_pipeline, isolation_threshold_metrics["threshold"],
                data["held_out_x"], data["held_out_y"], anomaly=True),
        },
        "attack_categories": attack_category_metrics(
            test_y, test_scores, rf_threshold_metrics["threshold"], data["test_categories"]),
        "warning": "Metrics are from synthetic data only and do not establish real-world detection efficacy.",
    }
    metrics_path = Path(metrics_path)
    metrics_path.parent.mkdir(parents=True, exist_ok=True)
    metrics_path.write_text(json.dumps(metrics, indent=2), encoding="utf-8")
    return metrics


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Train/evaluate models on the supplied synthetic snapshot.")
    parser.add_argument("--input", type=Path, default=DEFAULT_INPUT)
    parser.add_argument("--artifact", type=Path, default=DEFAULT_ARTIFACT)
    parser.add_argument("--metrics", type=Path, default=DEFAULT_METRICS)
    args = parser.parse_args()
    print(json.dumps(train(args.input, args.artifact, args.metrics), indent=2))
