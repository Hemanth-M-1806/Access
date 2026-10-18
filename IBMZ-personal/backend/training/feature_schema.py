"""
AccessDrift ML feature schema.

Defines approved input features and columns that must not be
passed directly into the anomaly detection model.
"""

from __future__ import annotations

import pandas as pd
from backend.data_generator import ROLE_BASELINES


# Numeric features observable from IAM profiles or access telemetry.
NUMERIC_FEATURES = [
    "permission_count",
    "critical_permission_count",
    "cross_department_permission_count",
    "unexpected_admin_count",
    "permission_changes_90d",
    "days_since_last_access",
    "failed_access_attempts_30d",
    "account_age_days",
    "access_grant_age_days",
    "is_service_account",
    "mfa_enabled",
    "permissions_above_role_median",
]

# Categorical attributes that are encoded during preprocessing.
CATEGORICAL_FEATURES = [
    "role",
    "department",
]

# Ground-truth labels. Never use these as model inputs.
TARGET_COLUMNS = [
    "is_anomalous",
    "anomaly_type",
]

# Dataset bookkeeping and scenario-generation metadata.
EXCLUDED_COLUMNS = [
    "user_id",
    "role_history",
    "permissions",
    "role_change_days_ago",
    "temporary_access_expired",
    "temporary_access_permission",
    "temporary_access_expiry_days",
    "approved_exception",
    "exception_approval_id",
    "exception_approved_by",
    "conflict_permission_1",
    "conflict_permission_2",
    "split",
]

# Complete approved feature set.
APPROVED_FEATURES = NUMERIC_FEATURES + CATEGORICAL_FEATURES


def compute_engineered_features(df: pd.DataFrame) -> pd.DataFrame:
    """
    Computes required engineered features (e.g. permissions_above_role_median)
    using the normative role baseline counts without data leakage.
    """
    df = df.copy()
    if "permissions_above_role_median" not in df.columns:
        role_baselines_count = {
            role: len(cfg["baseline_permissions"])
            for role, cfg in ROLE_BASELINES.items()
        }
        df["permissions_above_role_median"] = (
            df["permission_count"] - df["role"].map(role_baselines_count).fillna(0)
        )
    return df


def validate_feature_schema(df: pd.DataFrame) -> pd.DataFrame:
    """
    Validate that all approved features exist (computing engineered features if needed)
    and that no target, scenario metadata, or bookkeeping column is approved as a feature.

    Raises ValueError when the schema is inconsistent.
    """
    if "permissions_above_role_median" not in df.columns:
        df = compute_engineered_features(df)

    missing_features = [
        column
        for column in APPROVED_FEATURES
        if column not in df.columns
    ]

    if missing_features:
        raise ValueError(
            "Missing required ML features: "
            + ", ".join(missing_features)
        )

    forbidden_features = (
        set(TARGET_COLUMNS)
        | set(EXCLUDED_COLUMNS)
    )

    leakage_features = [
        column
        for column in APPROVED_FEATURES
        if column in forbidden_features
    ]

    if leakage_features:
        raise ValueError(
            "Potential data leakage detected in approved features: "
            + ", ".join(leakage_features)
        )

    print("ML feature schema validation passed.")
    print(f"Approved numeric features: {len(NUMERIC_FEATURES)}")
    print(
        "Approved categorical features: "
        f"{len(CATEGORICAL_FEATURES)}"
    )