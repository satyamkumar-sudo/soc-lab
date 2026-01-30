from __future__ import annotations

import json
import os
from typing import Any

import structlog

from storage.clickhouse_client import ClickHouseClient

log = structlog.get_logger(__name__)


DEFAULT_MODEL_CFG: dict[str, Any] = {
    "iforest": {"n_estimators": 200, "max_samples": "auto", "contamination": "auto", "random_state": 42},
    "autoencoder": {
        "hidden_layer_sizes": [16, 8, 16],
        "activation": "relu",
        "solver": "adam",
        "alpha": 0.0001,
        "learning_rate": "adaptive",
        "max_iter": 500,
        "random_state": 42,
    },
}


def train_and_write(model_path: str) -> None:
    """
    This lab uses a JSON model-config file (kept as `model.pkl` for legacy compatibility).
    The anomaly agent trains models online from ClickHouse `features` windows.
    """
    ch = ClickHouseClient()
    ch.wait_until_ready(timeout_s=60)

    # Heuristic tuning: adapt estimators based on available training windows.
    rows = ch.fetch_dicts("SELECT count() AS c FROM features")
    n = int(rows[0]["c"]) if rows else 0
    cfg = json.loads(json.dumps(DEFAULT_MODEL_CFG))
    if n >= 5000:
        cfg["iforest"]["n_estimators"] = 400
        cfg["autoencoder"]["hidden_layer_sizes"] = [32, 16, 32]
        cfg["autoencoder"]["max_iter"] = 800
    elif n >= 1000:
        cfg["iforest"]["n_estimators"] = 300
        cfg["autoencoder"]["hidden_layer_sizes"] = [24, 12, 24]

    os.makedirs(os.path.dirname(model_path), exist_ok=True)
    with open(model_path, "w") as f:
        json.dump(cfg, f, indent=2)
    log.info("model_config_written", model_path=model_path, feature_rows=n)


if __name__ == "__main__":
    model_path = os.environ.get("SOC_MODEL_PATH", "/app/ml/model.pkl")
    train_and_write(model_path)

