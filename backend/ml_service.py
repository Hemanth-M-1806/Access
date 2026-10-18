"""
AccessDrift Machine Learning Inference Service
==============================================
Provides high-performance production inference using the trained Phase 2
Isolation Forest Pipeline artifact and metadata.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import joblib
import numpy as np
import pandas as pd

from backend.data_generator import (
    ALL_PERMISSIONS,
    CRITICAL_PERMISSIONS,
    ROLE_BASELINES,
)
from backend.training.feature_schema import APPROVED_FEATURES

DEPARTMENT_PERMISSIONS = {
    "Engineering": {
        "github:repo_write", "jira:admin", "code:review",
        "k8s:namespace_read", "db:read", "s3:read", "slack:admin"
    },
    "DevOps": {
        "db:root", "k8s:admin", "cloud:iam_admin", "prod:deploy",
        "s3:backup_write", "k8s:namespace_read", "github:repo_write", "db:read"
    },
    "Finance": {
        "finance:gl_write", "finance:reports_read", "stripe:billing_admin",
        "s3:read", "hr:payroll_write"
    },
    "HR": {
        "hr:payroll_write", "hr:employee_pii_read", "hr:onboarding_admin",
        "slack:admin", "s3:read"
    },
}

MODELS_DIR = Path(__file__).resolve().parent / "models"
DEFAULT_MODEL_PATH = MODELS_DIR / "accessdrift_isolation_forest.joblib"
DEFAULT_METADATA_PATH = MODELS_DIR / "model_metadata.json"


class MLInferenceService:
    """
    Inference service wrapping the fitted scikit-learn Pipeline (ColumnTransformer + IsolationForest)
    and decision threshold for IAM entitlement anomaly detection.
    """

    def __init__(
        self,
        model_path: Optional[Path | str] = None,
        metadata_path: Optional[Path | str] = None,
    ):
        self.model_path = Path(model_path) if model_path else DEFAULT_MODEL_PATH
        self.metadata_path = Path(metadata_path) if metadata_path else DEFAULT_METADATA_PATH
        self.pipeline = None
        self.metadata = {}
        self.threshold = 0.055497
        self.score_convention = "score = -pipeline.decision_function(X)"
        self.load_artifacts()

    def load_artifacts(self) -> None:
        """Loads serialized model pipeline and metadata configuration."""
        if self.model_path.exists():
            try:
                self.pipeline = joblib.load(self.model_path)
            except Exception as e:
                print(f"[MLInferenceService] Warning: Failed to load model artifact: {e}")
                self.pipeline = None
        else:
            print(f"[MLInferenceService] Warning: Model artifact not found at {self.model_path}")

        if self.metadata_path.exists():
            with open(self.metadata_path, "r", encoding="utf-8") as f:
                self.metadata = json.load(f)
                self.threshold = float(self.metadata.get("selected_threshold", 0.055497))
        else:
            print(f"[MLInferenceService] Warning: Metadata artifact not found at {self.metadata_path}")

    @property
    def is_loaded(self) -> bool:
        return self.pipeline is not None

    def extract_features(self, user: Dict[str, Any]) -> Dict[str, Any]:
        """
        Extracts the 14 approved model features (12 numeric + 2 categorical)
        from a raw user access profile dictionary.
        """
        role = user.get("role", "Senior Software Engineer")
        department = user.get("department", "Engineering")
        permissions = set(user.get("permissions", []))

        # 1. Permission counts
        perm_count = len(permissions)
        critical_count = sum(p in CRITICAL_PERMISSIONS for p in permissions)

        dept_perms = DEPARTMENT_PERMISSIONS.get(department, set())
        cross_dept_count = sum(p not in dept_perms for p in permissions)

        role_baseline_cfg = ROLE_BASELINES.get(role, {"baseline_permissions": []})
        expected_perms = set(role_baseline_cfg.get("baseline_permissions", []))
        unexpected_admin_count = sum(
            p in CRITICAL_PERMISSIONS and p not in expected_perms for p in permissions
        )

        # Baseline median diff
        baseline_count = len(expected_perms)
        permissions_above_role_median = perm_count - baseline_count

        return {
            "permission_count": perm_count,
            "critical_permission_count": critical_count,
            "cross_department_permission_count": cross_dept_count,
            "unexpected_admin_count": unexpected_admin_count,
            "permission_changes_90d": user.get("permission_changes_90d", 0),
            "days_since_last_access": user.get("days_since_last_access", 3),
            "failed_access_attempts_30d": user.get("failed_access_attempts_30d", 0),
            "account_age_days": user.get("account_age_days", 365),
            "access_grant_age_days": user.get("access_grant_age_days", 90),
            "is_service_account": user.get("is_service_account", False),
            "mfa_enabled": user.get("mfa_enabled", True),
            "permissions_above_role_median": permissions_above_role_median,
            "role": role,
            "department": department,
        }

    def predict_user(self, user: Dict[str, Any]) -> Dict[str, Any]:
        """
        Runs ML model inference on a single user profile.
        Returns anomaly_score, is_outlier, risk_score (0-100), and threshold.
        """
        features = self.extract_features(user)
        df_row = pd.DataFrame([features])[APPROVED_FEATURES]

        if not self.is_loaded:
            return {
                "anomaly_score": 0.0,
                "is_outlier": False,
                "risk_score": 0,
                "threshold": self.threshold,
                "model_status": "UNLOADED",
            }

        # score = -decision_function(X) -> higher score indicates higher anomaly risk
        raw_score = float(-self.pipeline.decision_function(df_row)[0])
        is_outlier = raw_score >= self.threshold

        # Clamped risk score (0 to 100):
        # Maps threshold boundary (e.g. ~0.05) to risk threshold 40-75.
        # Below 0 is clean (0-30). Around threshold is moderate (40-60). Far above is critical (75-100).
        if raw_score <= 0.0:
            # Inlier: map [-0.15, 0.0] to [0, 25]
            risk_score = int(np.clip(25 * (1.0 + raw_score / 0.15), 0, 25))
        elif raw_score < self.threshold:
            # Slightly elevated but below threshold: map [0.0, threshold] to [26, 49]
            progress = raw_score / max(self.threshold, 1e-4)
            risk_score = int(26 + progress * 23)
        else:
            # Anomaly: map [threshold, threshold + 0.10] to [50, 100]
            excess = raw_score - self.threshold
            risk_score = int(np.clip(50 + (excess / 0.10) * 50, 50, 100))

        # Toxic privilege escalation override if user holds unexpected critical admin permissions
        if features["unexpected_admin_count"] > 0:
            risk_score = max(risk_score, 75)
            is_outlier = True

        return {
            "anomaly_score": round(raw_score, 5),
            "is_outlier": is_outlier,
            "risk_score": risk_score,
            "threshold": self.threshold,
            "model_status": "LOADED",
        }

    def predict_batch(self, users: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Batch inference for a list of user profile dicts."""
        feature_rows = [self.extract_features(u) for u in users]
        df = pd.DataFrame(feature_rows)[APPROVED_FEATURES]

        if not self.is_loaded:
            return [
                {
                    "anomaly_score": 0.0,
                    "is_outlier": False,
                    "risk_score": 0,
                    "threshold": self.threshold,
                    "model_status": "UNLOADED",
                }
                for _ in users
            ]

        raw_scores = -self.pipeline.decision_function(df)
        results = []
        for i, raw_score in enumerate(raw_scores):
            score = float(raw_score)
            is_outlier = score >= self.threshold
            features = feature_rows[i]

            if score <= 0.0:
                risk_score = int(np.clip(25 * (1.0 + score / 0.15), 0, 25))
            elif score < self.threshold:
                progress = score / max(self.threshold, 1e-4)
                risk_score = int(26 + progress * 23)
            else:
                excess = score - self.threshold
                risk_score = int(np.clip(50 + (excess / 0.10) * 50, 50, 100))

            if features["unexpected_admin_count"] > 0:
                risk_score = max(risk_score, 75)
                is_outlier = True

            results.append(
                {
                    "anomaly_score": round(score, 5),
                    "is_outlier": is_outlier,
                    "risk_score": risk_score,
                    "threshold": self.threshold,
                    "model_status": "LOADED",
                }
            )
        return results


# Global singleton instance for easy import across backend
ml_service = MLInferenceService()
