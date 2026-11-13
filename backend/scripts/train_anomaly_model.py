import json

from scripts.train import train


if __name__ == "__main__":
    report = train()
    print(json.dumps({
        "model": "IsolationForest",
        "fit_population": "normal training records only",
        "validation": report["isolation_forest_normal_only_fit"]["validation"],
        "test": report["isolation_forest_normal_only_fit"]["test"],
        "artifact": "artifacts/detection_model.joblib",
        "note": "The shared training workflow also refreshes the Random Forest classifier.",
    }, indent=2))
