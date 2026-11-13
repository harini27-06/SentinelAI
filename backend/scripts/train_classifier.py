import json

from scripts.train import train


if __name__ == "__main__":
    report = train()
    print(json.dumps({
        "model": "RandomForestClassifier",
        "validation": report["random_forest"]["validation"],
        "test": report["random_forest"]["test"],
        "artifact": "artifacts/detection_model.joblib",
        "note": "The shared training workflow also refreshes the normal-only Isolation Forest artifact.",
    }, indent=2))
