from pathlib import Path

import pandas as pd

from scripts.preprocess import LEAKAGE_COLUMNS, preprocess
from scripts.train import prepare_data, tune_threshold


def test_preprocess_preserves_labels_and_identifies_leakage():
    source = Path(__file__).with_name("preprocess_input_test.csv")
    output = Path(__file__).with_name("preprocess_output_test.csv")
    try:
        pd.DataFrame([
            {"event_id": "a", "label": 0, "attack_cat": "Normal", "rate": 1.0},
            {"event_id": "b", "label": 1, "attack_cat": "Attack", "rate": 2.0},
        ]).to_csv(source, index=False)
        result = preprocess(source, output)
        assert result["rows"] == 2
        assert "attack_cat" in LEAKAGE_COLUMNS
        frame, labels, excluded = prepare_data(output)
        assert frame.columns.tolist() == ["rate"]
        assert labels.tolist() == [0, 1]
        assert set(excluded) == {"attack_cat", "event_id"}
    finally:
        source.unlink(missing_ok=True)
        output.unlink(missing_ok=True)


def test_threshold_tuned_from_score_values():
    metrics = tune_threshold([0, 0, 1, 1], [0.1, 0.3, 0.7, 0.9])
    assert metrics["f1"] == 1.0
    assert metrics["threshold"] <= 0.7
