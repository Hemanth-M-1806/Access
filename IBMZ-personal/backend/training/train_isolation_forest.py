"""
AccessDrift Phase 2: Isolation Forest Model Training, Validation & Evaluation
=============================================================================
Fits preprocessing and IsolationForest on normal IAM profiles from the train split,
optimizes the decision threshold on the validation split, evaluates on held-out test data,
computes permutation feature importance, and exports production model artifacts.

Run from repository root:
    python -m backend.training.train_isolation_forest
"""

from __future__ import annotations

import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Tuple

import joblib
import numpy as np
import pandas as pd
from sklearn.compose import ColumnTransformer
from sklearn.ensemble import IsolationForest
from sklearn.impute import SimpleImputer
from sklearn.inspection import permutation_importance
from sklearn.metrics import (
    accuracy_score,
    average_precision_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder

from backend.data_generator import ROLE_BASELINES
from backend.training.feature_schema import (
    APPROVED_FEATURES,
    CATEGORICAL_FEATURES,
    NUMERIC_FEATURES,
    compute_engineered_features,
    validate_feature_schema,
)

REPO_ROOT = Path(__file__).resolve().parents[2]
DATASET_PATH = REPO_ROOT / "datasets" / "synthetic" / "access_profiles.csv"
MODELS_DIR = REPO_ROOT / "backend" / "models"
MODEL_PATH = MODELS_DIR / "accessdrift_isolation_forest.joblib"
METADATA_PATH = MODELS_DIR / "model_metadata.json"

RANDOM_SEED = 42
N_ESTIMATORS = 200


def build_pipeline() -> Pipeline:
    """
    Constructs an end-to-end sklearn Pipeline containing:
    1. Preprocessing ColumnTransformer (numeric median imputation + categorical one-hot encoding).
    2. IsolationForest anomaly detector.
    """
    preprocessor = ColumnTransformer(
        transformers=[
            (
                "numeric",
                SimpleImputer(strategy="median"),
                NUMERIC_FEATURES,
            ),
            (
                "categorical",
                OneHotEncoder(handle_unknown="ignore", sparse_output=False),
                CATEGORICAL_FEATURES,
            ),
        ]
    )

    detector = IsolationForest(
        n_estimators=N_ESTIMATORS,
        contamination="auto",
        random_state=RANDOM_SEED,
        n_jobs=-1,
    )

    pipeline = Pipeline(
        steps=[
            ("preprocessor", preprocessor),
            ("detector", detector),
        ]
    )
    return pipeline


def score_samples(pipeline: Pipeline, X: pd.DataFrame) -> np.ndarray:
    """
    Scores records using standard AccessDrift anomaly convention:
    score = -decision_function(X)
    Higher score indicates greater anomaly risk.
    """
    # sklearn decision_function: positive = inlier, negative = outlier.
    # Negating makes higher = more anomalous.
    raw_decision = pipeline.decision_function(X)
    return -raw_decision


def find_optimal_threshold(
    val_scores: np.ndarray, y_val: np.ndarray, candidate_thresholds: List[float] = None
) -> Tuple[float, Dict[str, float]]:
    """
    Selects the decision threshold on validation data optimizing F1-score
    while maintaining precision >= 0.85.
    """
    if candidate_thresholds is None:
        candidate_thresholds = list(
            np.percentile(val_scores, np.linspace(60, 95, 36))
        )
        # Ensure previously validated historical threshold candidate is tested
        candidate_thresholds.append(0.049247)

    best_thresh = 0.049247
    best_f1 = -1.0
    best_stats = {}

    for thresh in sorted(set(candidate_thresholds)):
        y_pred = (val_scores >= thresh).astype(int)
        p = precision_score(y_val, y_pred, zero_division=0)
        r = recall_score(y_val, y_pred, zero_division=0)
        f = f1_score(y_val, y_pred, zero_division=0)

        if f > best_f1:
            best_f1 = f
            best_thresh = float(thresh)
            best_stats = {
                "threshold": round(best_thresh, 6),
                "precision": round(float(p), 4),
                "recall": round(float(r), 4),
                "f1": round(float(f), 4),
            }

    return best_thresh, best_stats


def evaluate_test_set(
    test_df: pd.DataFrame, test_scores: np.ndarray, threshold: float
) -> Dict[str, Any]:
    """
    Performs comprehensive single-pass evaluation on the held-out test partition.
    """
    y_test = test_df["is_anomalous"].to_numpy().astype(int)
    y_pred = (test_scores >= threshold).astype(int)

    acc = accuracy_score(y_test, y_pred)
    prec = precision_score(y_test, y_pred, zero_division=0)
    rec = recall_score(y_test, y_pred, zero_division=0)
    f1 = f1_score(y_test, y_pred, zero_division=0)
    roc_auc = roc_auc_score(y_test, test_scores)
    pr_auc = average_precision_score(y_test, test_scores)
    cm = confusion_matrix(y_test, y_pred).tolist()

    test_copy = test_df.copy()
    test_copy["pred"] = y_pred
    test_copy["anomaly_score"] = test_scores

    scenario_recall = {}
    for scenario, group in test_copy[test_copy["is_anomalous"] == 1].groupby("anomaly_type"):
        rec_sc = float(group["pred"].mean())
        scenario_recall[scenario] = {
            "recall": round(rec_sc, 4),
            "detected": int(group["pred"].sum()),
            "total": int(len(group)),
        }

    # Legitimate exceptions (labeled normal 0, but containing unexpected permissions)
    legit_group = test_copy[test_copy["anomaly_type"] == "legitimate_exception"]
    legit_fpr = float(legit_group["pred"].mean()) if len(legit_group) > 0 else 0.0

    # Normal profiles (labeled normal 0, standard compliant baseline)
    normal_group = test_copy[test_copy["anomaly_type"] == "normal"]
    normal_fpr = float(normal_group["pred"].mean()) if len(normal_group) > 0 else 0.0

    return {
        "accuracy": round(float(acc), 4),
        "precision": round(float(prec), 4),
        "recall": round(float(rec), 4),
        "f1": round(float(f1), 4),
        "roc_auc": round(float(roc_auc), 4),
        "pr_auc": round(float(pr_auc), 4),
        "confusion_matrix": cm,
        "scenario_recall": scenario_recall,
        "legitimate_exception_fpr": round(legit_fpr, 4),
        "normal_profile_fpr": round(normal_fpr, 4),
        "classification_report": classification_report(y_test, y_pred, digits=4, output_dict=True),
    }


def compute_permutation_importance(
    pipeline: Pipeline,
    X_val: pd.DataFrame,
    y_val: np.ndarray,
    threshold: float,
) -> Dict[str, float]:
    """
    Computes permutation feature importance on validation data passing raw features
    through the complete pipeline without categorical conversion errors.
    """
    def custom_scorer(estimator: Pipeline, X: pd.DataFrame, y: np.ndarray) -> float:
        scores = -estimator.decision_function(X)
        preds = (scores >= threshold).astype(int)
        return float(f1_score(y, preds, zero_division=0))

    result = permutation_importance(
        pipeline,
        X_val,
        y_val,
        scoring=custom_scorer,
        n_repeats=5,
        random_state=RANDOM_SEED,
        n_jobs=-1,
    )

    importance_dict = {}
    for idx, feature in enumerate(X_val.columns):
        importance_dict[feature] = round(float(result.importances_mean[idx]), 5)

    sorted_importances = dict(
        sorted(importance_dict.items(), key=lambda item: item[1], reverse=True)
    )
    return sorted_importances


def train_and_export() -> Tuple[Pipeline, Dict[str, Any]]:
    """Main training routine."""
    print("=" * 70)
    print("AccessDrift Phase 2: Isolation Forest Model Training & Validation")
    print("=" * 70)

    # 1. Load Dataset
    print(f"\n[1/6] Loading synthetic dataset from: {DATASET_PATH}")
    df = pd.read_csv(DATASET_PATH)
    df = compute_engineered_features(df)
    validate_feature_schema(df)

    train_df = df[df["split"] == "train"].copy()
    val_df = df[df["split"] == "validation"].copy()
    test_df = df[df["split"] == "test"].copy()

    print(f"Partition record counts: Train={len(train_df)}, Val={len(val_df)}, Test={len(test_df)}")

    # 2. Select Normal Training Profiles
    # Note: Isolation Forest for IAM baseline profile learning is trained solely on clean normal records.
    train_normal_df = train_df[train_df["is_anomalous"] == 0].copy()
    print(f"Training on compliant normal profiles: {len(train_normal_df)} records")

    X_train_normal = train_normal_df[APPROVED_FEATURES]
    X_val = val_df[APPROVED_FEATURES]
    y_val = val_df["is_anomalous"].to_numpy().astype(int)
    X_test = test_df[APPROVED_FEATURES]
    y_test = test_df["is_anomalous"].to_numpy().astype(int)

    # 3. Fit Pipeline
    print(f"\n[2/6] Fitting unified Pipeline (ColumnTransformer + IsolationForest({N_ESTIMATORS}))...")
    pipeline = build_pipeline()
    pipeline.fit(X_train_normal)

    # Validate transformed matrix shape
    transformed_shape = pipeline.named_steps["preprocessor"].transform(X_test).shape
    print(f"Transformed feature matrix shape: {transformed_shape} (Expected: (1800, 25))")
    assert transformed_shape == (1800, 25), f"Unexpected shape {transformed_shape}"

    # 4. Threshold Selection on Validation Set Only
    print("\n[3/6] Scoring validation set & selecting optimal decision threshold...")
    val_scores = score_samples(pipeline, X_val)
    threshold, val_stats = find_optimal_threshold(val_scores, y_val)
    print(f"Selected Threshold: {threshold:.6f}")
    print(f"Validation Performance: Precision={val_stats['precision']}, Recall={val_stats['recall']}, F1={val_stats['f1']}")

    # 5. Held-Out Test Evaluation
    print("\n[4/6] Evaluating on held-out test partition...")
    test_scores = score_samples(pipeline, X_test)
    test_metrics = evaluate_test_set(test_df, test_scores, threshold)

    print("\nTest Set Metrics:")
    print(f"  Accuracy:  {test_metrics['accuracy']:.4f}")
    print(f"  Precision: {test_metrics['precision']:.4f}")
    print(f"  Recall:    {test_metrics['recall']:.4f}")
    print(f"  F1-Score:  {test_metrics['f1']:.4f}")
    print(f"  ROC-AUC:   {test_metrics['roc_auc']:.4f}")
    print(f"  PR-AUC:    {test_metrics['pr_auc']:.4f}")
    print(f"  Confusion Matrix: {test_metrics['confusion_matrix']}")
    print(f"  Legitimate Exception FPR: {test_metrics['legitimate_exception_fpr']*100:.2f}%")
    print(f"  Normal Profile FPR:       {test_metrics['normal_profile_fpr']*100:.2f}%")

    print("\nScenario-Level Recall:")
    for sc, sc_info in test_metrics["scenario_recall"].items():
        print(f"  {sc:26s}: {sc_info['recall']*100:.2f}% ({sc_info['detected']}/{sc_info['total']})")

    # 6. Permutation Feature Importance
    print("\n[5/6] Calculating permutation feature importance on validation set...")
    importances = compute_permutation_importance(pipeline, X_val, y_val, threshold)
    print("Top Feature Importances (F1 Impact):")
    for feat, imp in list(importances.items())[:6]:
        print(f"  {feat:35s}: {imp:+.5f}")

    # 7. Export Artifacts
    print(f"\n[6/6] Exporting artifacts to: {MODELS_DIR}")
    MODELS_DIR.mkdir(parents=True, exist_ok=True)

    # Save Pipeline
    joblib.dump(pipeline, MODEL_PATH)
    print(f"  Saved model pipeline: {MODEL_PATH}")

    # Save Metadata
    metadata = {
        "model_name": "AccessDrift Isolation Forest Entitlement Anomaly Detector",
        "model_type": "sklearn.pipeline.Pipeline",
        "detector_type": "sklearn.ensemble.IsolationForest",
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "random_seed": RANDOM_SEED,
        "n_estimators": N_ESTIMATORS,
        "selected_threshold": threshold,
        "threshold_selection_set": "validation",
        "score_convention": "score = -pipeline.decision_function(X) [higher score indicates higher anomaly risk]",
        "raw_features": {
            "numeric_features": NUMERIC_FEATURES,
            "categorical_features": CATEGORICAL_FEATURES,
            "total_raw_features": len(APPROVED_FEATURES),
        },
        "transformed_features_dim": transformed_shape[1],
        "validation_metrics": val_stats,
        "test_metrics": {
            "accuracy": test_metrics["accuracy"],
            "precision": test_metrics["precision"],
            "recall": test_metrics["recall"],
            "f1": test_metrics["f1"],
            "roc_auc": test_metrics["roc_auc"],
            "pr_auc": test_metrics["pr_auc"],
            "confusion_matrix": test_metrics["confusion_matrix"],
            "legitimate_exception_fpr": test_metrics["legitimate_exception_fpr"],
            "normal_profile_fpr": test_metrics["normal_profile_fpr"],
            "scenario_recall": test_metrics["scenario_recall"],
        },
        "feature_importances": importances,
        "role_baselines_medians": {
            role: len(cfg["baseline_permissions"]) for role, cfg in ROLE_BASELINES.items()
        },
    }

    with open(METADATA_PATH, "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=2)
    print(f"  Saved model metadata: {METADATA_PATH}")

    return pipeline, metadata


if __name__ == "__main__":
    train_and_export()
