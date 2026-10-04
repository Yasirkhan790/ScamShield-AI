from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
import json
import logging
import os

import joblib


logger = logging.getLogger(__name__)


DEFAULT_MODEL_PATH = (
    Path(__file__).resolve().parent
    / "artifacts"
    / "scamshield_text_model.joblib"
)

DEFAULT_METADATA_PATH = (
    Path(__file__).resolve().parent
    / "metadata.json"
)


@dataclass(frozen=True)
class MLAnalysisResult:
    status: str
    predicted_label: str | None
    scam_score: float | None
    model_version: str | None
    selected_threshold: float | None
    error: str | None = None


class ScamShieldTextClassifier:

    def __init__(
        self,
        model_path: Path,
        metadata_path: Path,
    ):
        self.model_path = model_path
        self.metadata_path = metadata_path

        self.model = None
        self.metadata: dict = {}

        self.ready = False
        self.load_error: str | None = None

        self._load()

    def _load(self):

        try:
            if not self.model_path.exists():
                raise FileNotFoundError(
                    f"Model artifact not found: "
                    f"{self.model_path}"
                )

            if not self.metadata_path.exists():
                raise FileNotFoundError(
                    f"Model metadata not found: "
                    f"{self.metadata_path}"
                )

            self.metadata = json.loads(
                self.metadata_path.read_text(
                    encoding="utf-8"
                )
            )

            self.model = joblib.load(
                self.model_path
            )

            classes = list(
                getattr(
                    self.model,
                    "classes_",
                    [],
                )
            )

            if "scam" not in classes:
                raise RuntimeError(
                    "Loaded model does not contain "
                    "'scam' class."
                )

            threshold = self.metadata.get(
                "selected_threshold"
            )

            if threshold is None:
                raise RuntimeError(
                    "Model metadata does not contain "
                    "selected_threshold."
                )

            self.ready = True

            logger.info(
                "ScamShield ML model loaded. "
                "version=%s",
                self.metadata.get(
                    "model_version",
                    "unknown",
                ),
            )

        except Exception as exc:

            self.ready = False
            self.load_error = str(exc)

            logger.exception(
                "ScamShield ML model could not load."
            )

    @property
    def model_version(self) -> str | None:

        value = self.metadata.get(
            "model_version"
        )

        if value is None:
            return None

        return str(value)

    @property
    def selected_threshold(self) -> float | None:

        value = self.metadata.get(
            "selected_threshold"
        )

        if value is None:
            return None

        return float(value)

    def analyze(
        self,
        text: str,
    ) -> MLAnalysisResult:

        if not self.ready or self.model is None:

            return MLAnalysisResult(
                status="fallback",
                predicted_label=None,
                scam_score=None,
                model_version=self.model_version,
                selected_threshold=
                    self.selected_threshold,
                error=self.load_error
                or "ML classifier unavailable",
            )

        try:
            probabilities = (
                self.model.predict_proba(
                    [text]
                )[0]
            )

            classes = list(
                self.model.classes_
            )

            scam_index = classes.index(
                "scam"
            )

            scam_score = float(
                probabilities[
                    scam_index
                ]
            )

            threshold = float(
                self.selected_threshold
            )

            prediction = (
                "scam"
                if scam_score >= threshold
                else "legitimate"
            )

            return MLAnalysisResult(
                status="used",
                predicted_label=prediction,
                scam_score=scam_score,
                model_version=self.model_version,
                selected_threshold=threshold,
            )

        except Exception as exc:

            logger.exception(
                "ScamShield ML inference failed."
            )

            return MLAnalysisResult(
                status="fallback",
                predicted_label=None,
                scam_score=None,
                model_version=self.model_version,
                selected_threshold=
                    self.selected_threshold,
                error=str(exc),
            )


def _ml_enabled() -> bool:

    raw = os.getenv(
        "ML_ENABLED",
        "true",
    )

    return (
        raw.strip().lower()
        not in {
            "0",
            "false",
            "no",
            "off",
            "disabled",
        }
    )


def _model_path() -> Path:

    configured = os.getenv(
        "ML_MODEL_PATH"
    )

    if configured:
        return Path(configured)

    return DEFAULT_MODEL_PATH


@lru_cache(maxsize=1)
def get_ml_classifier(
) -> ScamShieldTextClassifier | None:

    if not _ml_enabled():
        return None

    return ScamShieldTextClassifier(
        model_path=_model_path(),
        metadata_path=DEFAULT_METADATA_PATH,
    )


def analyze_text_with_ml(
    text: str,
) -> MLAnalysisResult:

    classifier = get_ml_classifier()

    if classifier is None:

        return MLAnalysisResult(
            status="disabled",
            predicted_label=None,
            scam_score=None,
            model_version=None,
            selected_threshold=None,
            error=None,
        )

    return classifier.analyze(
        text
    )


def ml_health() -> dict:

    classifier = get_ml_classifier()

    if classifier is None:

        return {
            "status": "disabled",
            "ready": False,
            "model_version": None,
            "selected_threshold": None,
        }

    return {
        "status":
            "ready"
            if classifier.ready
            else "fallback",

        "ready":
            classifier.ready,

        "model_version":
            classifier.model_version,

        "selected_threshold":
            classifier.selected_threshold,
    }