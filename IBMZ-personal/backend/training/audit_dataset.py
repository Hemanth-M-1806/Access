"""
AccessDrift Dataset Quality Audit
=================================

Inspects the generated synthetic dataset before ML training.

Run from the repository root:

    python -m backend.training.audit_dataset
"""

import json
from pathlib import Path

import pandas as pd

import ast
import json

from backend.training.feature_schema import validate_feature_schema

from backend.data_generator import (
    ALL_PERMISSIONS,
    CRITICAL_PERMISSIONS,
    ROLE_BASELINES,
)


DATASET_PATH = (
    Path(__file__).resolve().parents[2]
    / "datasets"
    / "synthetic"
    / "access_profiles.csv"
)


def load_dataset() -> pd.DataFrame:
    """Load the generated dataset."""

    if not DATASET_PATH.exists():
        raise FileNotFoundError(
            f"Dataset not found: {DATASET_PATH}"
        )

    return pd.read_csv(DATASET_PATH)


def parse_json_column(df: pd.DataFrame) -> pd.DataFrame:
    """Decode JSON-encoded permission and role-history fields."""

    df = df.copy()

    df["permissions"] = df["permissions"].apply(json.loads)
    df["role_history"] = df["role_history"].apply(json.loads)

    return df


def audit_basic_integrity(df: pd.DataFrame) -> None:
    """Check fundamental dataset properties."""

    print("\n" + "=" * 65)
    print("1. BASIC DATASET INTEGRITY")
    print("=" * 65)

    print(f"Total records: {len(df)}")
    print(f"Unique user IDs: {df['user_id'].nunique()}")
    print(f"Missing values:\n{df.isna().sum()}")

    assert df["user_id"].is_unique, "Duplicate user IDs detected."

    assert set(df["is_anomalous"].unique()).issubset({0, 1}), (
        "Unexpected label values."
    )

    assert set(df["split"].unique()) == {
        "train",
        "validation",
        "test",
    }, "Unexpected dataset partitions."

    print("\nBasic integrity checks passed.")


def audit_scenario_distribution(df: pd.DataFrame) -> None:
    """Inspect scenario counts and ground-truth labels."""

    print("\n" + "=" * 65)
    print("2. SCENARIO AND LABEL DISTRIBUTION")
    print("=" * 65)

    scenario_table = pd.crosstab(
        df["anomaly_type"],
        df["is_anomalous"],
        margins=True,
    )

    print(scenario_table)

    print("\nScenario distribution by partition:")

    print(
        pd.crosstab(
            df["anomaly_type"],
            df["split"],
        )
    )


def audit_feature_distributions(df: pd.DataFrame) -> None:
    """Inspect whether scenario features differ as intended."""

    print("\n" + "=" * 65)
    print("3. FEATURE DISTRIBUTIONS BY SCENARIO")
    print("=" * 65)

    numeric_features = [
        "permission_count",
        "critical_permission_count",
        "cross_department_permission_count",
        "unexpected_admin_count",
        "permission_changes_90d",
        "days_since_last_access",
        "failed_access_attempts_30d",
        "account_age_days",
        "access_grant_age_days",
    ]

    print(
        df.groupby("anomaly_type")[numeric_features]
        .mean()
        .round(2)
        .to_string()
    )


def audit_normal_profiles(df: pd.DataFrame) -> None:
    """Check whether normal profiles follow their role baselines."""

    print("\n" + "=" * 65)
    print("4. NORMAL PROFILE BASELINE CHECK")
    print("=" * 65)

    normal_df = df[df["anomaly_type"] == "normal"]

    results = []

    for _, row in normal_df.iterrows():
        expected = set(
            ROLE_BASELINES[row["role"]]["baseline_permissions"]
        )

        actual = set(row["permissions"])

        missing = expected - actual
        extra = actual - expected

        results.append({
            "role": row["role"],
            "missing_baseline_permissions": len(missing),
            "extra_permissions": len(extra),
        })

    results_df = pd.DataFrame(results)

    print(
        results_df.groupby("role")[
            [
                "missing_baseline_permissions",
                "extra_permissions",
            ]
        ]
        .mean()
        .round(3)
        .to_string()
    )

    print(
        "\nNote: small baseline deviations can be intentional, "
        "because the generator allows occasional missing "
        "noncritical permissions."
    )


def audit_critical_permissions(df: pd.DataFrame) -> None:
    """Inspect critical permissions in normal and anomalous profiles."""

    print("\n" + "=" * 65)
    print("5. CRITICAL PERMISSION AUDIT")
    print("=" * 65)

    critical_permissions = set(CRITICAL_PERMISSIONS)

    records = []

    for _, row in df.iterrows():
        actual = set(row["permissions"])

        expected = set(
            ROLE_BASELINES[row["role"]]["baseline_permissions"]
        )

        critical_present = actual & critical_permissions

        unexpected_critical = (
            critical_present - expected
        )

        records.append({
            "user_id": row["user_id"],
            "role": row["role"],
            "department": row["department"],
            "anomaly_type": row["anomaly_type"],
            "critical_permissions": len(critical_present),
            "unexpected_critical_permissions": len(
                unexpected_critical
            ),
            "unexpected_critical_list": sorted(
                unexpected_critical
            ),
        })

    audit_df = pd.DataFrame(records)

    print(
        audit_df.groupby("anomaly_type")[
            [
                "critical_permissions",
                "unexpected_critical_permissions",
            ]
        ]
        .mean()
        .round(3)
        .to_string()
    )

    print("\nExamples of unexpected critical permissions:")

    examples = audit_df[
        audit_df["unexpected_critical_permissions"] > 0
    ].head(10)

    print(examples.to_string(index=False))


def audit_exceptions(df: pd.DataFrame) -> None:
    """Verify that legitimate exceptions are represented."""

    print("\n" + "=" * 65)
    print("6. LEGITIMATE EXCEPTION AUDIT")
    print("=" * 65)

    exceptions = df[df["anomaly_type"] == "legitimate_exception"]

    print(f"Exception records: {len(exceptions)}")

    print(
        "Approved exception values:\n",
        exceptions["approved_exception"].value_counts(
            dropna=False
        ),
    )

    print("\nRepresentative exceptions:")

    columns = [
        "user_id",
        "role",
        "department",
        "permission_count",
        "cross_department_permission_count",
        "unexpected_admin_count",
        "approved_exception",
        "is_anomalous",
    ]

    print(exceptions[columns].head(10).to_string(index=False))


def audit_permissions(df: pd.DataFrame) -> None:
    """Check permission validity and duplication."""

    print("\n" + "=" * 65)
    print("7. PERMISSION VALIDATION")
    print("=" * 65)

    valid_permissions = set(ALL_PERMISSIONS)

    invalid_records = []
    duplicate_records = []

    for _, row in df.iterrows():
        permissions = row["permissions"]

        invalid = set(permissions) - valid_permissions

        if invalid:
            invalid_records.append(
                (row["user_id"], sorted(invalid))
            )

        if len(permissions) != len(set(permissions)):
            duplicate_records.append(row["user_id"])

    print(f"Invalid permission records: {len(invalid_records)}")
    print(f"Duplicate permission records: {len(duplicate_records)}")

    assert not invalid_records, "Unknown permissions detected."
    assert not duplicate_records, "Duplicate permissions detected."

    print("Permission validation passed.")

def audit_exception_approval_metadata(
    df: pd.DataFrame,
) -> None:
    """Validate synthetic approval metadata."""

    exceptions = df[
        df["anomaly_type"] == "legitimate_exception"
    ]

    invalid = exceptions[
        (
            exceptions["approved_exception"] != True
        )
        | (
            exceptions["exception_approval_id"].isna()
        )
        | (
            exceptions["exception_approved_by"].isna()
        )
    ]

    print("\nLegitimate exception approval audit")
    print(f"Total exceptions: {len(exceptions)}")
    print(f"Invalid approval records: {len(invalid)}")

    if not invalid.empty:
        raise ValueError(
            "Some legitimate exceptions lack valid approval metadata."
        )

def audit_temporary_access(
    df: pd.DataFrame,
) -> None:
    """Validate expired temporary access records."""

    expired = df[
        df["anomaly_type"] == "expired_temporary_access"
    ]

    invalid = expired[
        (
            expired["temporary_access_expired"] != True
        )
        | (
            expired["temporary_access_permission"].isna()
        )
        | (
            expired["temporary_access_expiry_days"].isna()
        )
        | (
            expired["temporary_access_expiry_days"] >= 0
        )
    ]

    print("\nTemporary access audit")
    print(f"Expired-access records: {len(expired)}")
    print(f"Invalid records: {len(invalid)}")

    if not invalid.empty:
        raise ValueError(
            "Invalid expired temporary access records detected."
        )

def parse_permissions(value):
    """
    Convert a serialized permissions field into a Python set.

    Supports JSON arrays, Python-list representations, and
    pipe-separated permission strings.
    """

    if isinstance(value, (list, tuple, set)):
        return set(value)

    if not isinstance(value, str) or not value.strip():
        return set()

    # Preferred format: JSON array.
    try:
        parsed = json.loads(value)

        if isinstance(parsed, (list, tuple, set)):
            return set(parsed)

    except (json.JSONDecodeError, TypeError):
        pass

    # Fallback: Python-list representation.
    try:
        parsed = ast.literal_eval(value)

        if isinstance(parsed, (list, tuple, set)):
            return set(parsed)

    except (ValueError, SyntaxError):
        pass

    # Fallback: pipe-separated string.
    if "|" in value:
        return {
            item.strip()
            for item in value.split("|")
            if item.strip()
        }

    return {value.strip()}

def audit_scenario_semantics(df):
    """
    Verify that scenario-specific metadata and permissions
    agree with the scenario assigned to each record.
    """

    print("\nScenario semantic audit")

    required_columns = [
        "permissions",
        "anomaly_type",
        "is_anomalous",
        "temporary_access_expired",
        "temporary_access_permission",
        "temporary_access_expiry_days",
        "conflict_permission_1",
        "conflict_permission_2",
        "role_change_days_ago",
        "permission_changes_90d",
        "approved_exception",
        "exception_approval_id",
        "exception_approved_by",
    ]

    missing = [
        column
        for column in required_columns
        if column not in df.columns
    ]

    if missing:
        raise ValueError(
            "Cannot complete scenario semantic audit. "
            "Missing columns: "
            + ", ".join(missing)
        )

    errors = []

    for _, row in df.iterrows():
        scenario = row["anomaly_type"]
        permissions = parse_permissions(row["permissions"])

        # --------------------------------------------------
        # 1. Conflicting permissions
        # --------------------------------------------------
        if scenario == "conflicting_permissions":
            first = row["conflict_permission_1"]
            second = row["conflict_permission_2"]

            if pd.isna(first) or pd.isna(second):
                errors.append(
                    f"{row['user_id']}: missing conflict metadata"
                )

            elif first not in permissions or second not in permissions:
                errors.append(
                    f"{row['user_id']}: designated conflict pair "
                    "is not fully present in permissions"
                )

            if int(row["is_anomalous"]) != 1:
                errors.append(
                    f"{row['user_id']}: conflicting permissions "
                    "must have anomaly label 1"
                )

        # --------------------------------------------------
        # 2. Expired temporary access
        # --------------------------------------------------
        elif scenario == "expired_temporary_access":
            temporary_permission = row[
                "temporary_access_permission"
            ]

            expiry_days = row["temporary_access_expiry_days"]

            if pd.isna(temporary_permission):
                errors.append(
                    f"{row['user_id']}: missing temporary permission"
                )

            elif temporary_permission not in permissions:
                errors.append(
                    f"{row['user_id']}: temporary permission "
                    "is absent from the permission set"
                )

            if pd.isna(expiry_days) or float(expiry_days) >= 0:
                errors.append(
                    f"{row['user_id']}: expiry days must be negative"
                )

            if not bool(row["temporary_access_expired"]):
                errors.append(
                    f"{row['user_id']}: expired-access flag is false"
                )

            if int(row["is_anomalous"]) != 1:
                errors.append(
                    f"{row['user_id']}: expired temporary access "
                    "must have anomaly label 1"
                )

        # --------------------------------------------------
        # 3. Legitimate exceptions
        # --------------------------------------------------
        elif scenario == "legitimate_exception":
            if int(row["is_anomalous"]) != 0:
                errors.append(
                    f"{row['user_id']}: legitimate exception "
                    "must have anomaly label 0"
                )

            if not bool(row["approved_exception"]):
                errors.append(
                    f"{row['user_id']}: legitimate exception "
                    "is not marked as approved"
                )

            if pd.isna(row["exception_approval_id"]):
                errors.append(
                    f"{row['user_id']}: missing approval ID"
                )

            if pd.isna(row["exception_approved_by"]):
                errors.append(
                    f"{row['user_id']}: missing approver"
                )

        # --------------------------------------------------
        # 4. Privilege creep
        # --------------------------------------------------
        elif scenario == "privilege_creep":
            if pd.isna(row["role_change_days_ago"]):
                errors.append(
                    f"{row['user_id']}: privilege creep has "
                    "no recorded role-change age"
                )

            if int(row["permission_changes_90d"]) <= 0:
                errors.append(
                    f"{row['user_id']}: privilege creep must "
                    "record at least one permission change"
                )

            if int(row["is_anomalous"]) != 1:
                errors.append(
                    f"{row['user_id']}: privilege creep "
                    "must have anomaly label 1"
                )

    if errors:
        print(f"Scenario semantic audit failed: {len(errors)} issue(s)")

        for error in errors[:20]:
            print(f"  - {error}")

        if len(errors) > 20:
            print(f"  ... and {len(errors) - 20} additional issue(s)")

        raise ValueError(
            "Scenario semantic audit failed. "
            "Fix the generator before training."
        )

    print("Scenario semantic audit passed.")

def audit_ml_feature_schema(df):
    """
    Confirm that the dataset satisfies the approved ML feature schema.
    """

    print("\nML feature schema audit")

    validate_feature_schema(df)

    print("Feature schema audit passed.")

def main() -> None:
    print("AccessDrift Synthetic Dataset Audit")

    df = load_dataset()
    df = parse_json_column(df)

    audit_basic_integrity(df)
    audit_scenario_distribution(df)
    audit_feature_distributions(df)
    audit_normal_profiles(df)
    audit_critical_permissions(df)
    audit_exceptions(df)
    audit_permissions(df)
    audit_exception_approval_metadata(df)
    audit_temporary_access(df)
    audit_scenario_semantics(df)
    audit_ml_feature_schema(df)

    print("\n" + "=" * 65)
    print("AUDIT COMPLETED")
    print("=" * 65)

    print(
        "\nReview the scenario feature distributions before "
        "using this dataset for ML training."
    )


if __name__ == "__main__":
    main()