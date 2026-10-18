"""
AccessDrift Phase 2 ML Model & Inference Test Suite
===================================================
Validates:
- Artifact existence and metadata integrity
- Pipeline loading and transformation shapes
- Correct anomaly scoring convention (higher score = more anomalous)
- Threshold adherence and prediction correctness on normal vs anomalous IAM profiles
- ML inference service integration
"""

import json
import unittest
from pathlib import Path
import joblib
import numpy as np
import pandas as pd

from backend.ml_service import MLInferenceService, ml_service
from backend.training.feature_schema import APPROVED_FEATURES, NUMERIC_FEATURES, CATEGORICAL_FEATURES

REPO_ROOT = Path(__file__).resolve().parents[2]
MODELS_DIR = REPO_ROOT / "backend" / "models"
MODEL_PATH = MODELS_DIR / "accessdrift_isolation_forest.joblib"
METADATA_PATH = MODELS_DIR / "model_metadata.json"


class TestMLInference(unittest.TestCase):

    def test_01_artifacts_exist_and_metadata_valid(self):
        self.assertTrue(MODEL_PATH.exists(), f"Model artifact missing at {MODEL_PATH}")
        self.assertTrue(METADATA_PATH.exists(), f"Metadata missing at {METADATA_PATH}")

        with open(METADATA_PATH, "r", encoding="utf-8") as f:
            meta = json.load(f)

        self.assertIn("selected_threshold", meta)
        self.assertIn("score_convention", meta)
        self.assertIn("test_metrics", meta)
        self.assertGreater(meta["test_metrics"]["roc_auc"], 0.95)
        self.assertGreater(meta["test_metrics"]["pr_auc"], 0.90)
        self.assertGreater(meta["test_metrics"]["f1"], 0.85)

    def test_02_pipeline_load_and_transform_shape(self):
        pipeline = joblib.load(MODEL_PATH)
        self.assertIsNotNone(pipeline)

        # Create dummy batch of 2 records
        dummy_df = pd.DataFrame([
            {
                "permission_count": 5,
                "critical_permission_count": 1,
                "cross_department_permission_count": 0,
                "unexpected_admin_count": 0,
                "permission_changes_90d": 1,
                "days_since_last_access": 3,
                "failed_access_attempts_30d": 0,
                "account_age_days": 400,
                "access_grant_age_days": 100,
                "is_service_account": False,
                "mfa_enabled": True,
                "permissions_above_role_median": 0,
                "role": "Senior Software Engineer",
                "department": "Engineering",
            },
            {
                "permission_count": 8,
                "critical_permission_count": 3,
                "cross_department_permission_count": 2,
                "unexpected_admin_count": 2,
                "permission_changes_90d": 6,
                "days_since_last_access": 15,
                "failed_access_attempts_30d": 2,
                "account_age_days": 300,
                "access_grant_age_days": 50,
                "is_service_account": False,
                "mfa_enabled": False,
                "permissions_above_role_median": 3,
                "role": "DevOps Engineer",
                "department": "DevOps",
            }
        ])[APPROVED_FEATURES]

        preprocessor = pipeline.named_steps["preprocessor"]
        transformed = preprocessor.transform(dummy_df)
        self.assertEqual(transformed.shape, (2, 25))

        # Check raw decision function executes without string conversion errors
        decision = pipeline.decision_function(dummy_df)
        self.assertEqual(len(decision), 2)

    def test_03_score_convention_and_directionality(self):
        service = MLInferenceService(MODEL_PATH, METADATA_PATH)
        self.assertTrue(service.is_loaded)

        normal_user = {
            "role": "Senior Software Engineer",
            "department": "Engineering",
            "permissions": ["github:repo_write", "code:review", "db:read", "k8s:namespace_read", "s3:read"],
            "days_since_last_access": 1,
            "failed_access_attempts_30d": 0,
            "mfa_enabled": True,
        }

        toxic_admin_user = {
            "role": "Payroll Specialist",
            "department": "Finance",
            "permissions": ["hr:payroll_write", "finance:gl_write", "finance:reports_read", "db:root", "k8s:admin", "cloud:iam_admin"],
            "days_since_last_access": 45,
            "failed_access_attempts_30d": 3,
            "mfa_enabled": False,
        }

        norm_pred = service.predict_user(normal_user)
        anom_pred = service.predict_user(toxic_admin_user)

        # Higher score must indicate higher anomaly
        self.assertGreater(anom_pred["anomaly_score"], norm_pred["anomaly_score"])
        self.assertFalse(norm_pred["is_outlier"])
        self.assertTrue(anom_pred["is_outlier"])
        self.assertGreaterEqual(anom_pred["risk_score"], 75)
        self.assertLessEqual(norm_pred["risk_score"], 35)

    def test_04_batch_inference_consistency(self):
        service = MLInferenceService(MODEL_PATH, METADATA_PATH)
        users = [
            {
                "id": "u1",
                "role": "Frontend Engineer",
                "department": "Engineering",
                "permissions": ["github:repo_write", "code:review", "s3:read"],
            },
            {
                "id": "u2",
                "role": "HR Generalist",
                "department": "HR",
                "permissions": ["hr:employee_pii_read", "hr:onboarding_admin", "prod:deploy", "cloud:iam_admin"],
            }
        ]

        batch_preds = service.predict_batch(users)
        self.assertEqual(len(batch_preds), 2)
        self.assertFalse(batch_preds[0]["is_outlier"])
        self.assertTrue(batch_preds[1]["is_outlier"])


if __name__ == "__main__":
    unittest.main()
