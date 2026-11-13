import argparse
from pathlib import Path

import numpy as np
import pandas as pd

BASE_DIR = Path(__file__).resolve().parents[1]
DEFAULT_INPUT = BASE_DIR / "data" / "raw" / "sentinelai_synthetic_cleaned.csv"
DEFAULT_OUTPUT = BASE_DIR / "data" / "processed" / "flows_preprocessed.csv"

LEAKAGE_COLUMNS = {
    "label", "attack_cat", "event_id", "timestamp", "endpoint_id", "agent_type",
    "source", "scenario", "synthetic", "id",
}


def preprocess(input_path=DEFAULT_INPUT, output_path=DEFAULT_OUTPUT):
    frame = pd.read_csv(input_path)
    if "label" not in frame.columns:
        raise ValueError("Input dataset must contain a binary label column")
    frame["label"] = pd.to_numeric(frame["label"], errors="raise").astype(int)
    if not set(frame["label"].unique()).issubset({0, 1}):
        raise ValueError("Label column must contain only 0 and 1")
    frame = frame.drop_duplicates(subset=["event_id"] if "event_id" in frame else None)
    frame = frame.replace([np.inf, -np.inf], np.nan)
    for column in frame.select_dtypes(include=["object", "string"]).columns:
        frame[column] = frame[column].fillna("unknown").astype(str)
    for column in frame.select_dtypes(include="number").columns:
        if column != "label":
            median = frame[column].median()
            if pd.notna(median):
                frame[column] = frame[column].fillna(median)
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    frame.to_csv(output_path, index=False)
    return {
        "rows": len(frame),
        "columns": len(frame.columns),
        "output": str(output_path),
        "label_distribution": {str(int(label)): int(count) for label, count in frame["label"].value_counts().items()},
        "remaining_missing_values": int(frame.isna().sum().sum()),
        "excluded_from_features": sorted(LEAKAGE_COLUMNS),
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Preprocess the supplied synthetic flows without altering raw snapshots.")
    parser.add_argument("--input", type=Path, default=DEFAULT_INPUT)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()
    print(preprocess(args.input, args.output))
