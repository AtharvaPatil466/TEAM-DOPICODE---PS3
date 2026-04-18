"""Shadow-device detection via IsolationForest.

Design: we extract a small fixed-length feature vector from each scanned
internal asset, fit an IsolationForest on a synthetic baseline of "legitimate
corporate device" profiles (servers, workstations, DBs), and flag outliers as
shadow devices. The CICIDS-2017 dataset is where a real model would be trained;
that path is preserved via `load_model_from_disk()` which consumes a pickled
estimator if present.

The in-memory baseline is good enough for the demo — the rogue alpine sshd
container and the busybox IoT simulator are clear outliers vs corporate Linux
servers and workstations.
"""
import logging
import os
import pickle
from dataclasses import dataclass

import numpy as np
from sklearn.ensemble import IsolationForest

from backend.db.models import Asset

log = logging.getLogger(__name__)

MODEL_PATH = os.getenv("ANOMALY_MODEL_PATH", "")
FEATURE_DIM = 10


@dataclass
class AnomalyResult:
    asset_id: int
    is_shadow: bool
    score: float  # higher = more anomalous (we negate IF decision_function)


def _feature_vector(asset: Asset) -> np.ndarray:
    ports = [p.port_number for p in asset.ports if p.state == "open"]
    services = {(p.service_name or "").lower() for p in asset.ports}
    port_set = set(ports)

    has_ssh = 1 if 22 in port_set else 0
    has_http = 1 if port_set & {80, 8080} else 0
    has_https = 1 if port_set & {443, 8443} else 0
    has_db = 1 if port_set & {3306, 5432, 6379, 27017, 9200} else 0
    has_smb = 1 if port_set & {139, 445} else 0
    has_telnet = 1 if 23 in port_set else 0
    os_known = 1 if asset.os_guess else 0
    port_count = len(ports)
    service_diversity = len(services - {""})
    high_port_ratio = (sum(1 for p in ports if p > 10000) / port_count) if port_count else 0.0

    return np.array([
        port_count,
        has_ssh, has_http, has_https, has_db, has_smb, has_telnet,
        os_known, service_diversity, high_port_ratio,
    ], dtype=float)


def _synthetic_baseline(n: int = 300, seed: int = 42) -> np.ndarray:
    """Generate feature vectors representative of legitimate corporate devices:
    web servers (http/https + ssh), DB servers (db port + ssh), workstations
    (smb + ssh, OS known). IoT-with-no-OS and random-high-port devices are NOT
    in the baseline — so the forest treats them as outliers."""
    rng = np.random.default_rng(seed)
    rows: list[list[float]] = []

    # Web servers
    for _ in range(n // 3):
        rows.append([
            rng.integers(2, 6),   # port count
            1,                    # ssh
            1, rng.choice([0, 1]),  # http / https
            0, 0, 0,
            1,                    # os known
            rng.integers(2, 5),   # service diversity
            0.0,
        ])
    # DB servers
    for _ in range(n // 3):
        rows.append([
            rng.integers(2, 4),
            1, 0, 0,
            1, 0, 0,
            1,
            rng.integers(2, 4),
            0.0,
        ])
    # Workstations
    for _ in range(n - 2 * (n // 3)):
        rows.append([
            rng.integers(3, 7),
            1, 0, 0,
            0, 1, 0,
            1,
            rng.integers(3, 6),
            rng.uniform(0.0, 0.2),
        ])
    return np.array(rows, dtype=float)


class AnomalyDetector:
    def __init__(self, contamination: float = 0.1) -> None:
        self.model: IsolationForest | None = None
        self.contamination = contamination

    def load_or_train(self) -> None:
        if MODEL_PATH and os.path.exists(MODEL_PATH):
            try:
                with open(MODEL_PATH, "rb") as f:
                    self.model = pickle.load(f)
                log.info("Loaded anomaly model from %s", MODEL_PATH)
                return
            except Exception as e:
                log.warning("Failed to load %s: %s", MODEL_PATH, e)
        X = _synthetic_baseline()
        self.model = IsolationForest(
            n_estimators=100,
            contamination=self.contamination,
            random_state=42,
        )
        self.model.fit(X)
        log.info("Fitted synthetic IsolationForest baseline (n=%d)", len(X))

    def classify(self, assets: list[Asset]) -> list[AnomalyResult]:
        if self.model is None:
            self.load_or_train()
        if not assets:
            return []
        X = np.vstack([_feature_vector(a) for a in assets])
        preds = self.model.predict(X)           # 1 = inlier, -1 = outlier
        scores = -self.model.decision_function(X)  # higher = more anomalous
        out: list[AnomalyResult] = []
        for a, p, s in zip(assets, preds, scores):
            out.append(AnomalyResult(
                asset_id=a.id,
                is_shadow=bool(p == -1),
                score=float(s),
            ))
        return out


_detector: AnomalyDetector | None = None


def get_detector() -> AnomalyDetector:
    global _detector
    if _detector is None:
        _detector = AnomalyDetector()
        _detector.load_or_train()
    return _detector
