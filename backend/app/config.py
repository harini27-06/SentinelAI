import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parents[1]
DATABASE_URL = os.getenv("SENTINELAI_DATABASE_URL", f"sqlite:///{BASE_DIR / 'sentinelai.db'}")
MODEL_PATH = Path(os.getenv("SENTINELAI_MODEL_PATH", str(BASE_DIR / "artifacts" / "detection_model.joblib")))
ALLOWED_ORIGINS = os.getenv(
    "SENTINELAI_CORS_ORIGINS",
    "http://localhost:5173,http://127.0.0.1:5173",
).split(",")
CORRELATION_WINDOW_SECONDS = int(os.getenv("SENTINELAI_CORRELATION_WINDOW_SECONDS", "600"))
