"""
AccessDrift Synthetic IAM Dataset Generator
============================================

Generates synthetic enterprise identity and access-management profiles
for developing and evaluating anomaly detection models.

Output:
    datasets/synthetic/access_profiles.csv
    datasets/synthetic/dataset_summary.json
    datasets/synthetic/dataset_manifest.json

Run from the repository root:

    python -m backend.training.generate_dataset

This generator does not modify the live application dataset.
"""

from __future__ import annotations

import hashlib
import json
import random
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd

from backend.data_generator import (
    ALL_PERMISSIONS,
    CRITICAL_PERMISSIONS,
    ROLE_BASELINES,
)


# ============================================================
# 1. CONFIGURATION
# ============================================================

RANDOM_SEED = 42

TOTAL_RECORDS = 12_000

# Scenario proportions must sum to 1.0.
SCENARIO_DISTRIBUTION = {
    "normal": 0.70,
    "privilege_creep": 0.08,
    "cross_department": 0.05,
    "excessive_admin": 0.05,
    "dormant_permission": 0.04,
    "expired_temporary_access": 0.03,
    "conflicting_permissions": 0.03,
    "legitimate_exception": 0.02,
}

TRAIN_RATIO = 0.70
VALIDATION_RATIO = 0.15
TEST_RATIO = 0.15

OUTPUT_DIR = (
    Path(__file__).resolve().parents[2]
    / "datasets"
    / "synthetic"
)

# Each scenario has an explicit ground-truth label.
ANOMALY_LABELS = {
    "normal": 0,
    "privilege_creep": 1,
    "cross_department": 1,
    "excessive_admin": 1,
    "dormant_permission": 1,
    "expired_temporary_access": 1,
    "conflicting_permissions": 1,
    "legitimate_exception": 0,
}

# Permissions associated with specific departments.
DEPARTMENT_PERMISSIONS = {
    "Engineering": {
        "github:repo_write",
        "jira:admin",
        "code:review",
        "k8s:namespace_read",
        "db:read",
        "s3:read",
        "slack:admin",
    },
    "DevOps": {
        "db:root",
        "k8s:admin",
        "cloud:iam_admin",
        "prod:deploy",
        "s3:backup_write",
        "k8s:namespace_read",
        "github:repo_write",
        "db:read",
    },
    "Finance": {
        "finance:gl_write",
        "finance:reports_read",
        "stripe:billing_admin",
        "s3:read",
        "hr:payroll_write",
    },
    "HR": {
        "hr:payroll_write",
        "hr:employee_pii_read",
        "hr:onboarding_admin",
        "slack:admin",
        "s3:read",
    },
}

# ============================================================
# ENTERPRISE ACCESS POLICY DEFINITIONS
# ============================================================

# These are synthetic policy assumptions for the AccessDrift demo.
# They are NOT universal enterprise security rules.
#
# Each pair represents permissions that our hypothetical
# organization considers incompatible when held simultaneously.

CONFLICTING_PERMISSION_PAIRS = [
    ("finance:gl_write", "stripe:billing_admin"),
    ("hr:payroll_write", "cloud:iam_admin"),
    ("db:root", "hr:employee_pii_read"),
]

# Temporary permissions must have an explicit expiration state.
TEMPORARY_ACCESS_PERMISSIONS = {
    "cloud:iam_admin",
    "prod:deploy",
    "db:root",
    "k8s:admin",
    "stripe:billing_admin",
}

# Synthetic approval rules:
# A legitimate exception must have a documented approval
# and an associated permission.
#
# These rules are for dataset generation, not production IAM.

LEGITIMATE_EXCEPTION_PROBABILITY = 0.5

# Controls how often privilege creep is subtle rather than severe.
SUBTLE_PRIVILEGE_CREEP_PROBABILITY = 0.70


# ============================================================
# 2. VALIDATE CONFIGURATION
# ============================================================

def validate_configuration() -> None:
    """Fail early if dataset configuration is inconsistent."""

    total_probability = sum(SCENARIO_DISTRIBUTION.values())

    if not np.isclose(total_probability, 1.0):
        raise ValueError(
            f"Scenario probabilities must sum to 1.0; "
            f"got {total_probability:.4f}"
        )

    if TOTAL_RECORDS <= 0:
        raise ValueError("TOTAL_RECORDS must be positive.")

    if not np.isclose(
        TRAIN_RATIO + VALIDATION_RATIO + TEST_RATIO,
        1.0,
    ):
        raise ValueError(
            "Train, validation, and test ratios must sum to 1.0."
        )

    if set(ANOMALY_LABELS) != set(SCENARIO_DISTRIBUTION):
        raise ValueError(
            "Every scenario must have exactly one ground-truth label."
        )

    known_permissions = set(ALL_PERMISSIONS)

    for role, config in ROLE_BASELINES.items():
        invalid = set(config["baseline_permissions"]) - known_permissions

        if invalid:
            raise ValueError(
                f"Role {role!r} has unknown permissions: {sorted(invalid)}"
            )

    for department, permissions in DEPARTMENT_PERMISSIONS.items():
        invalid = permissions - known_permissions

        if invalid:
            raise ValueError(
                f"Department {department!r} has unknown permissions: "
                f"{sorted(invalid)}"
            )


# ============================================================
# 3. RANDOMNESS AND HELPER FUNCTIONS
# ============================================================

def initialize_randomness(seed: int = RANDOM_SEED) -> None:
    """Initialize random number generators for reproducibility."""

    random.seed(seed)
    np.random.seed(seed)


def weighted_choice(
    distribution: dict[str, float],
) -> str:
    """Select a scenario using its configured probability."""

    scenarios = list(distribution.keys())
    probabilities = list(distribution.values())

    return str(
        np.random.choice(
            scenarios,
            p=probabilities,
        )
    )


def generate_user_id(index: int) -> str:
    """Generate a deterministic, unique synthetic user identifier."""

    return f"syn_{index:06d}"


def choose_role() -> str:
    """Choose a role from the existing enterprise role definitions."""

    return random.choice(list(ROLE_BASELINES.keys()))


def get_role_context(role: str) -> dict[str, Any]:
    """Return the authoritative baseline for a role."""

    if role not in ROLE_BASELINES:
        raise ValueError(f"Unknown role: {role}")

    return ROLE_BASELINES[role]


def generate_normal_permissions(role: str) -> list[str]:
    """
    Generate a plausible access profile for a role.

    Most records retain their complete role baseline.
    A small number have a missing noncritical permission.
    """

    baseline = list(
        get_role_context(role)["baseline_permissions"]
    )

    permissions = set(baseline)

    # Simulate occasional legitimate access variation.
    if len(permissions) > 2 and random.random() < 0.08:
        removable = [
            p for p in permissions
            if p not in CRITICAL_PERMISSIONS
        ]

        if removable:
            permissions.remove(random.choice(removable))

    return sorted(permissions)


def add_unexpected_permission(
    permissions: set[str],
    department: str,
    *,
    critical_only: bool = False,
) -> str | None:
    """Add one permission outside the expected department profile."""

    if critical_only:
        candidates = set(CRITICAL_PERMISSIONS)
    else:
        candidates = set(ALL_PERMISSIONS)

    candidates -= permissions
    candidates -= DEPARTMENT_PERMISSIONS.get(department, set())

    if not candidates:
        return None

    selected = random.choice(sorted(candidates))
    permissions.add(selected)

    return selected


# ============================================================
# 4. SYNTHETIC EMPLOYEE GENERATION
# ============================================================

def generate_base_profile(
    index: int,
    scenario: str,
) -> dict[str, Any]:
    """Create identity and access-management attributes."""

    role = choose_role()
    context = get_role_context(role)
    department = context["department"]

    permissions = set(
        generate_normal_permissions(role)
    )

    role_history = [role]

    role_change_days_ago = None
    permission_changes_90d = random.randint(0, 3)

    days_since_last_access = random.randint(0, 14)
    failed_access_attempts_30d = random.randint(0, 2)

    temporary_access_expired = False
    approved_exception = False

    account_age_days = random.randint(30, 2500)
    access_grant_age_days = random.randint(1, 730)

    # Scenario-specific behavior is added in the next step.

    return {
        "user_id": generate_user_id(index),
        "role": role,
        "department": department,
        "role_history": role_history,
        "permissions": permissions,
        "role_change_days_ago": role_change_days_ago,
        "permission_changes_90d": permission_changes_90d,
        "days_since_last_access": days_since_last_access,
        "failed_access_attempts_30d": failed_access_attempts_30d,
        "temporary_access_expired": temporary_access_expired,
        "temporary_access_permission": None,
        "temporary_access_expiry_days": None,
        "approved_exception": approved_exception,
        "exception_approval_id": None,
        "exception_approved_by": None,
        "account_age_days": account_age_days,
        "access_grant_age_days": access_grant_age_days,
        "conflict_permission_1": None,
        "conflict_permission_2": None,
        "is_service_account": False,
        "mfa_enabled": random.random() < 0.95,
        "scenario": scenario,
    }


def apply_scenario(
    profile: dict[str, Any],
) -> dict[str, Any]:
    """
    Modify a normal profile to represent its assigned scenario.

    The anomaly_type is retained for evaluation and explanation.
    It must NOT be passed into the model as an input feature.
    """

    scenario = profile["scenario"]
    permissions = profile["permissions"]
    department = profile["department"]
    role = profile["role"]

    if scenario == "normal":
        pass

    elif scenario == "privilege_creep":
        # Simulate a role transition where permissions from the
        # previous role were not fully removed.

        old_roles = [
            r for r in ROLE_BASELINES
            if r != role
        ]

        old_role = random.choice(old_roles)

        old_permissions = set(
            ROLE_BASELINES[old_role]["baseline_permissions"]
        )

        # Permissions inherited from the former role but not
        # included in the current role's baseline.
        retained_permissions = (
            old_permissions - permissions
        )

        # Most cases are subtle: retain only one or two permissions.
        # The remainder represent more severe privilege creep.
        if random.random() < SUBTLE_PRIVILEGE_CREEP_PROBABILITY:
            max_retained = min(
                2,
                len(retained_permissions),
            )

            if max_retained > 0:
                retained_permissions = set(
                    random.sample(
                        sorted(retained_permissions),
                        k=random.randint(1, max_retained),
                    )
                )
        else:
            # Preserve the more severe cases.
            retained_permissions = set(retained_permissions)

        permissions.update(retained_permissions)

        # If the previous role has no unique permissions,
        # add a permission outside the current role baseline.
        if not retained_permissions:
            add_unexpected_permission(
                permissions,
                department,
            )

        profile["role_history"] = [
            old_role,
            role,
        ]

        profile["role_change_days_ago"] = random.randint(
            1,
            90,
        )

        profile["permission_changes_90d"] = random.randint(
            1,
            8,
        )

    elif scenario == "cross_department":
        # Add access associated with another department.
        other_departments = [
            d for d in DEPARTMENT_PERMISSIONS
            if d != department
        ]

        other_department = random.choice(other_departments)

        candidates = (
            DEPARTMENT_PERMISSIONS[other_department]
            - permissions
        )

        if candidates:
            permissions.add(
                random.choice(sorted(candidates))
            )

        profile["permission_changes_90d"] = random.randint(2, 10)

    elif scenario == "excessive_admin":
        # Add an unexpected critical administrative permission.
        selected = add_unexpected_permission(
            permissions,
            department,
            critical_only=True,
        )

        if selected is None:
            # Some roles legitimately need critical permissions.
            # Add a second unexpected permission when possible.
            add_unexpected_permission(
                permissions,
                department,
            )

        profile["permission_changes_90d"] = random.randint(2, 10)

    elif scenario == "dormant_permission":
        # Model a sensitive permission with no recent usage.
        # In this synthetic dataset, days_since_last_access
        # refers to the permission under investigation.
        critical_candidates = set(CRITICAL_PERMISSIONS) & permissions

        if not critical_candidates:
            selected = add_unexpected_permission(
                permissions,
                department,
                critical_only=True,
            )
        else:
            selected = random.choice(sorted(critical_candidates))

        profile["days_since_last_access"] = random.randint(120, 730)
        profile["access_grant_age_days"] = random.randint(180, 1500)

        if selected is None:
            # Mark the scenario as invalid rather than silently
            # creating a normal profile with a dormant label.
            profile["scenario_generation_failed"] = True

    elif scenario == "expired_temporary_access":
        # Select a temporary permission that is not already assigned.

        candidates = (
            TEMPORARY_ACCESS_PERMISSIONS - permissions
        )

        if not candidates:
            profile["scenario_generation_failed"] = True

        else:
            selected_permission = random.choice(
                sorted(candidates)
            )

            permissions.add(selected_permission)

            profile["temporary_access_expired"] = True

            profile["temporary_access_permission"] = (
                selected_permission
            )

            # Negative means the expiration date is in the past.
            # For example, -12 means it expired 12 days ago.
            profile["temporary_access_expiry_days"] = -random.randint(
                1,
                90,
            )

            profile["access_grant_age_days"] = random.randint(
                30,
                365,
            )

            profile["permission_changes_90d"] = random.randint(
                1,
                8,
            )

    elif scenario == "conflicting_permissions":
        # Choose an explicit policy conflict.
        pair = random.choice(
            CONFLICTING_PERMISSION_PAIRS
        )

        first_permission, second_permission = pair

        # The scenario is only valid if both permissions exist
        # in the enterprise permission universe.
        if (
            first_permission not in ALL_PERMISSIONS
            or second_permission not in ALL_PERMISSIONS
        ):
            profile["scenario_generation_failed"] = True

        else:
            # Both permissions must be present for the configured
            # conflict rule to apply.
            permissions.update(pair)

            profile["conflict_permission_1"] = (
                first_permission
            )

            profile["conflict_permission_2"] = (
                second_permission
            )

            profile["permission_changes_90d"] = random.randint(
                1,
                8,
            )

    elif scenario == "legitimate_exception":
        # An unusual permission may be legitimate when an approved
        # exception exists.

        selected = add_unexpected_permission(
            permissions,
            department,
        )

        if selected is None:
            profile["scenario_generation_failed"] = True

        else:
            profile["approved_exception"] = True

            # Synthetic approval metadata.
            profile["exception_approval_id"] = (
                f"EXC-{profile['user_id']}"
            )

            profile["exception_approved_by"] = random.choice(
                [
                    "security_manager",
                    "department_manager",
                    "iam_governance_team",
                ]
            )

            profile["permission_changes_90d"] = random.randint(
                1,
                5,
            )
    else:
        raise ValueError(f"Unsupported scenario: {scenario}")

    return profile


def profile_to_record(
    profile: dict[str, Any],
) -> dict[str, Any]:
    """Convert a profile into a flat, CSV-compatible record."""

    permissions = sorted(profile["permissions"])

    critical_count = sum(
        permission in CRITICAL_PERMISSIONS
        for permission in permissions
    )

    department_permissions = DEPARTMENT_PERMISSIONS[
        profile["department"]
    ]

    cross_department_count = sum(
        permission not in department_permissions
        for permission in permissions
    )

    expected_permissions = set(
        ROLE_BASELINES[profile["role"]]["baseline_permissions"]
    )

    unexpected_admin_count = sum(
        permission in CRITICAL_PERMISSIONS
        and permission not in expected_permissions
        for permission in permissions
    )

    scenario = profile["scenario"]

    return {
        "user_id": profile["user_id"],
        "role": profile["role"],
        "department": profile["department"],
        "role_history": json.dumps(profile["role_history"]),
        "permissions": json.dumps(permissions),
        "permission_count": len(permissions),
        "critical_permission_count": critical_count,
        "cross_department_permission_count": cross_department_count,
        "unexpected_admin_count": unexpected_admin_count,
        "role_change_days_ago": profile["role_change_days_ago"],
        "permission_changes_90d": profile["permission_changes_90d"],
        "days_since_last_access": profile["days_since_last_access"],
        "failed_access_attempts_30d": profile["failed_access_attempts_30d"],
        "temporary_access_expired": profile["temporary_access_expired"],
        "temporary_access_permission": profile["temporary_access_permission"],
        "temporary_access_expiry_days": profile["temporary_access_expiry_days"],
        "approved_exception": profile["approved_exception"],
        "exception_approval_id": profile["exception_approval_id"],
        "exception_approved_by": profile["exception_approved_by"],
        "conflict_permission_1": profile["conflict_permission_1"],
        "conflict_permission_2": profile["conflict_permission_2"],
        "account_age_days": profile["account_age_days"],
        "access_grant_age_days": profile["access_grant_age_days"],
        "is_service_account": profile["is_service_account"],
        "mfa_enabled": profile["mfa_enabled"],
        "is_anomalous": ANOMALY_LABELS[scenario],
        "anomaly_type": scenario,
    }


# ============================================================
# 5. BUILD THE DATASET
# ============================================================

def generate_dataset(
    total_records: int = TOTAL_RECORDS,
    seed: int = RANDOM_SEED,
) -> pd.DataFrame:
    """Generate a reproducible synthetic IAM dataset."""

    if total_records <= 0:
        raise ValueError("total_records must be positive.")

    validate_configuration()
    initialize_randomness(seed)

    # Use largest-remainder allocation so scenario counts sum
    # exactly to total_records.
    exact_counts = {
        name: proportion * total_records
        for name, proportion in SCENARIO_DISTRIBUTION.items()
    }

    counts = {
        name: int(value)
        for name, value in exact_counts.items()
    }

    remainder = total_records - sum(counts.values())

    fractional_order = sorted(
        SCENARIO_DISTRIBUTION,
        key=lambda name: (
            exact_counts[name] - counts[name]
        ),
        reverse=True,
    )

    for name in fractional_order[:remainder]:
        counts[name] += 1

    records = []
    index = 1

    for scenario, count in counts.items():
        for _ in range(count):
            profile = generate_base_profile(index, scenario)
            profile = apply_scenario(profile)
            if profile is None:
                raise RuntimeError(
                    f"apply_scenario() returned None for scenario: {scenario}. "
                    "Check that every branch returns the profile."
                )
            attempts = 0
            while profile.get("scenario_generation_failed", False):
                attempts += 1

                if attempts >= 20:
                    raise RuntimeError(
                        f"Could not generate valid scenario "
                        f"{scenario!r} after 20 attempts."
                    )

                profile = generate_base_profile(index, scenario)
                profile = apply_scenario(profile)

                if profile is None:
                    raise RuntimeError(
                        f"apply_scenario() returned None for scenario: {scenario}. "
                        "Check that every branch returns the profile."
                    )

            records.append(profile_to_record(profile))
            index += 1

    df = pd.DataFrame(records)

    # Shuffle record order without changing record identities.
    df = df.sample(
        frac=1.0,
        random_state=seed,
    ).reset_index(drop=True)

    # Create partitions.
    # Scenario-stratified splitting is preferable here because
    # some anomaly types are uncommon.
    from sklearn.model_selection import train_test_split

    df["split"] = ""

    remaining_indices = df.index

    for scenario in df["anomaly_type"].unique():
        scenario_indices = df.index[
            df["anomaly_type"] == scenario
        ].to_numpy()

        train_idx, remainder_idx = train_test_split(
            scenario_indices,
            test_size=VALIDATION_RATIO + TEST_RATIO,
            random_state=seed,
        )

        validation_fraction = (
            VALIDATION_RATIO
            / (VALIDATION_RATIO + TEST_RATIO)
        )

        validation_idx, test_idx = train_test_split(
            remainder_idx,
            test_size=1.0 - validation_fraction,
            random_state=seed,
        )

        df.loc[train_idx, "split"] = "train"
        df.loc[validation_idx, "split"] = "validation"
        df.loc[test_idx, "split"] = "test"

    if (df["split"] == "").any():
        raise RuntimeError("Some records were not assigned a split.")

    return df

def validate_scenario_semantics(df):
    """
    Validate critical scenario invariants before exporting the dataset.
    """

    required_columns = [
        "anomaly_type",
        "is_anomalous",
        "permissions",
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
            "Scenario validation failed. Missing columns: "
            + ", ".join(missing)
        )

    errors = []

    for _, row in df.iterrows():
        scenario = row["anomaly_type"]

        # Conflicting permissions must have both designated permissions.
        if scenario == "conflicting_permissions":
            first = row["conflict_permission_1"]
            second = row["conflict_permission_2"]
            permissions = set(
                json.loads(row["permissions"])
                if isinstance(row["permissions"], str)
                and row["permissions"].strip().startswith("[")
                else row["permissions"]
            )

            if pd.isna(first) or pd.isna(second):
                errors.append(
                    f"{row['user_id']}: missing conflict pair"
                )
            elif first not in permissions or second not in permissions:
                errors.append(
                    f"{row['user_id']}: incomplete conflict pair"
                )

            if int(row["is_anomalous"]) != 1:
                errors.append(
                    f"{row['user_id']}: incorrect conflict label"
                )

        # Expired temporary access must have a permission and a negative
        # expiry value.
        elif scenario == "expired_temporary_access":
            temporary_permission = row[
                "temporary_access_permission"
            ]
            expiry_days = row["temporary_access_expiry_days"]

            if pd.isna(temporary_permission):
                errors.append(
                    f"{row['user_id']}: missing temporary permission"
                )

            if pd.isna(expiry_days) or float(expiry_days) >= 0:
                errors.append(
                    f"{row['user_id']}: invalid expiry days"
                )

            if not bool(row["temporary_access_expired"]):
                errors.append(
                    f"{row['user_id']}: expired flag is false"
                )

        # Legitimate exceptions need an explicit approval trail.
        elif scenario == "legitimate_exception":
            if int(row["is_anomalous"]) != 0:
                errors.append(
                    f"{row['user_id']}: incorrect exception label"
                )

            if not bool(row["approved_exception"]):
                errors.append(
                    f"{row['user_id']}: exception is not approved"
                )

            if (
                pd.isna(row["exception_approval_id"])
                or pd.isna(row["exception_approved_by"])
            ):
                errors.append(
                    f"{row['user_id']}: incomplete approval metadata"
                )

        # Privilege creep must record a role change and permission change.
        elif scenario == "privilege_creep":
            if pd.isna(row["role_change_days_ago"]):
                errors.append(
                    f"{row['user_id']}: missing role-change age"
                )

            if int(row["permission_changes_90d"]) <= 0:
                errors.append(
                    f"{row['user_id']}: no permission changes recorded"
                )

    if errors:
        for error in errors[:20]:
            print(f"  - {error}")

        raise ValueError(
            f"Scenario validation failed with {len(errors)} issue(s)."
        )

    print("Scenario semantic validation passed.")


# ============================================================
# 6. DATASET VALIDATION
# ============================================================

def validate_dataset(df: pd.DataFrame) -> None:
    """Validate core dataset invariants before exporting."""

    required_columns = {
        "user_id",
        "role",
        "department",
        "permissions",
        "permission_count",
        "is_anomalous",
        "anomaly_type",
        "split",
    }

    missing = required_columns - set(df.columns)

    if missing:
        raise ValueError(
            f"Dataset is missing required columns: {sorted(missing)}"
        )

    if df.empty:
        raise ValueError("Dataset is empty.")

    if df["user_id"].duplicated().any():
        raise ValueError("Duplicate synthetic user IDs detected.")

    if df["is_anomalous"].isna().any():
        raise ValueError("Missing anomaly labels detected.")

    if not set(df["is_anomalous"].unique()).issubset({0, 1}):
        raise ValueError("Anomaly labels must be binary: 0 or 1.")

    if set(df["split"].unique()) != {"train", "validation", "test"}:
        raise ValueError("One or more dataset partitions are missing.")

    if len(df) != df["user_id"].nunique():
        raise ValueError("Record count does not match unique user count.")

    valid_permissions = set(ALL_PERMISSIONS)

    for raw_permissions in df["permissions"]:
        permissions = json.loads(raw_permissions)

        if not set(permissions).issubset(valid_permissions):
            raise ValueError(
                "Unknown permission found in a generated record."
            )

        if len(permissions) != len(set(permissions)):
            raise ValueError(
                "Duplicate permission found in a generated record."
            )

    # Each unique synthetic identity must occur in exactly one split.
    split_counts = df.groupby("user_id")["split"].nunique()

    if (split_counts != 1).any():
        raise ValueError("Identity leakage detected across splits.")

    # Ground-truth labels must match the scenario definitions.
    for _, row in df.iterrows():
        expected = ANOMALY_LABELS[row["anomaly_type"]]

        if int(row["is_anomalous"]) != expected:
            raise ValueError(
                f"Incorrect label for scenario {row['anomaly_type']!r}."
            )

    # Verify that all scenarios have sufficient examples in all splits.
    scenario_counts = df.groupby(
        ["anomaly_type", "split"]
    ).size()

    if (scenario_counts == 0).any():
        raise ValueError(
            "At least one scenario is absent from a dataset partition."
        )


# ============================================================
# 7. EXPORT DATASET AND METADATA
# ============================================================

def export_dataset(
    df: pd.DataFrame,
    output_dir: Path = OUTPUT_DIR,
    seed: int = RANDOM_SEED,
) -> None:
    """Export the CSV dataset and reproducibility metadata."""

    output_dir.mkdir(
        parents=True,
        exist_ok=True,
    )

    csv_path = output_dir / "access_profiles.csv"

    # Fixed column order makes outputs easier to compare.
    df.to_csv(
        csv_path,
        index=False,
    )

    scenario_counts = (
        df["anomaly_type"]
        .value_counts()
        .sort_index()
        .to_dict()
    )

    split_counts = (
        df["split"]
        .value_counts()
        .sort_index()
        .to_dict()
    )

    label_counts = (
        df["is_anomalous"]
        .value_counts()
        .sort_index()
        .to_dict()
    )

    summary = {
        "dataset_name": "AccessDrift Synthetic IAM Dataset",
        "record_count": int(len(df)),
        "seed": seed,
        "scenario_distribution_config": SCENARIO_DISTRIBUTION,
        "scenario_counts": {
            key: int(value)
            for key, value in scenario_counts.items()
        },
        "label_counts": {
            str(key): int(value)
            for key, value in label_counts.items()
        },
        "split_counts": {
            key: int(value)
            for key, value in split_counts.items()
        },
        "role_counts": {
            key: int(value)
            for key, value in df["role"].value_counts().items()
        },
        "department_counts": {
            key: int(value)
            for key, value in df["department"].value_counts().items()
        },
        "generated_at_utc": datetime.now(
            timezone.utc
        ).isoformat(),
        "data_is_synthetic": True,
        "model_training_note": (
            "Use only normal records from the train partition "
            "to fit the initial Isolation Forest model. "
            "Exclude is_anomalous, anomaly_type, split, user_id, "
            "and other identifier or ground-truth fields from "
            "model input features."
        ),
    }

    summary_path = output_dir / "dataset_summary.json"

    summary_path.write_text(
        json.dumps(summary, indent=2),
        encoding="utf-8",
    )

    csv_hash = hashlib.sha256(
        csv_path.read_bytes()
    ).hexdigest()

    manifest = {
        "dataset_file": csv_path.name,
        "sha256": csv_hash,
        "record_count": len(df),
        "seed": seed,
        "schema_version": "1.0.0",
        "generated_at_utc": datetime.now(
            timezone.utc
        ).isoformat(),
    }

    manifest_path = output_dir / "dataset_manifest.json"

    manifest_path.write_text(
        json.dumps(manifest, indent=2),
        encoding="utf-8",
    )

    print("\nDataset exported successfully.")
    print(f"CSV:     {csv_path}")
    print(f"Summary: {summary_path}")
    print(f"Manifest:{manifest_path}")
    print(f"SHA-256: {csv_hash}")


# ============================================================
# 8. ENTRY POINT
# ============================================================

def main() -> None:
    """Run generation, validation, and export."""

    print("=" * 60)
    print("AccessDrift Synthetic IAM Dataset Generator")
    print("=" * 60)

    print("\n[1/3] Generating synthetic records...")

    df = generate_dataset()

    print(f"Generated {len(df):,} records.")

    print("\n[2/3] Validating dataset...")

    validate_dataset(df)
    validate_scenario_semantics(df)

    print("Dataset validation passed.")

    print("\n[3/3] Exporting dataset...")

    export_dataset(df)

    print("\nScenario distribution:")
    print(df["anomaly_type"].value_counts().sort_index())

    print("\nGround-truth label distribution:")
    print(df["is_anomalous"].value_counts().sort_index())

    print("\nDataset partition distribution:")
    print(df["split"].value_counts().sort_index())

    print("\nFirst five records:")
    print(
        df[
            [
                "user_id",
                "role",
                "department",
                "permission_count",
                "is_anomalous",
                "anomaly_type",
                "split",
            ]
        ].head()
    )


if __name__ == "__main__":
    main()
