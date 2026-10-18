"""
AccessDrift Core Mathematical & Anomaly Engine
Calculates Role Centroids, Zero-Safe Cosine Distance, Clamped Risk Scores, and Drift Attribution.
"""

import math
import numpy as np
from typing import List, Dict, Any, Tuple
from .data_generator import ALL_PERMISSIONS, CRITICAL_PERMISSIONS, ROLE_BASELINES
from .ml_service import ml_service


class AnomalyEngine:
    """
    High-performance, ultra-lean vector mathematical engine (< 1MB RAM footprint).
    """

    def __init__(self, permissions_universe: List[str] = None):
        self.permissions = permissions_universe or ALL_PERMISSIONS
        self.perm_to_idx = {p: i for i, p in enumerate(self.permissions)}
        self.num_perms = len(self.permissions)

    def encode_user_vector(self, user_permissions: List[str]) -> np.ndarray:
        """Encodes user permission strings into a binary vector in {0, 1}^M."""
        vec = np.zeros(self.num_perms, dtype=np.float32)
        for p in user_permissions:
            if p in self.perm_to_idx:
                vec[self.perm_to_idx[p]] = 1.0
        return vec

    def decode_vector(self, vec: np.ndarray, threshold: float = 0.5) -> List[str]:
        """Decodes binary/continuous vector back into list of permission names."""
        return [self.permissions[i] for i, val in enumerate(vec) if val >= threshold]

    def compute_role_centroids(self, users: List[Dict[str, Any]]) -> Dict[str, np.ndarray]:
        """
        Computes role centroid vectors: mu_R anchored by normative role baseline specifications
        plus empirical compliant peer vectors, preventing a single outlier from poisoning small groups.
        """
        role_vectors: Dict[str, List[np.ndarray]] = {}
        
        # Include normative baseline definition as ground-truth anchor (weight = 3 peer equivalents)
        for role, config in ROLE_BASELINES.items():
            baseline_vec = self.encode_user_vector(config["baseline_permissions"])
            role_vectors.setdefault(role, []).extend([baseline_vec, baseline_vec, baseline_vec])

        # Include empirical users
        for u in users:
            role = u["role"]
            v = self.encode_user_vector(u["permissions"])
            role_vectors.setdefault(role, []).append(v)
            
        centroids: Dict[str, np.ndarray] = {}
        for role, vectors in role_vectors.items():
            centroids[role] = np.mean(vectors, axis=0)
                
        return centroids


    def compute_zero_safe_cosine_distance(self, user_vec: np.ndarray, centroid_vec: np.ndarray) -> float:
        """
        Computes entitlement divergence with strict zero-magnitude protection:
        Distance = 1.0 if ||v||_2 == 0 or ||mu||_2 == 0
        Distance = 1.0 - (v . mu) / (||v||_2 * ||mu||_2) otherwise.
        """
        user_norm = np.linalg.norm(user_vec)
        centroid_norm = np.linalg.norm(centroid_vec)
        
        if user_norm == 0.0 or centroid_norm == 0.0:
            return 1.0
            
        dot_product = np.dot(user_vec, centroid_vec)
        cosine_sim = float(dot_product / (user_norm * centroid_norm))
        # Prevent floating point rounding exceeding [-1.0, 1.0]
        cosine_sim = max(-1.0, min(1.0, cosine_sim))
        
        return max(0.0, 1.0 - cosine_sim)

    def calculate_user_risk(
        self,
        user: Dict[str, Any],
        centroid_vec: np.ndarray
    ) -> Tuple[int, float, List[str], List[str], float]:
        """
        Calculates user risk score, drift permissions, and explainability metrics.
        Returns: (risk_score, cosine_distance, drift_permissions, missing_permissions, alpha_multiplier)
        """
        user_vec = self.encode_user_vector(user["permissions"])
        distance = self.compute_zero_safe_cosine_distance(user_vec, centroid_vec)
        
        # Identify specific drifted and missing permissions
        drift_perms: List[str] = []
        for p in user["permissions"]:
            idx = self.perm_to_idx.get(p)
            if idx is not None:
                # If peer group has low ownership (< 35%) for this permission, it is an anomaly
                if centroid_vec[idx] < 0.35:
                    drift_perms.append(p)
                    
        missing_perms: List[str] = []
        for i, val in enumerate(centroid_vec):
            # If peer group commonly possesses (>= 60%) but user is missing
            if val >= 0.60 and user_vec[i] == 0.0:
                missing_perms.append(self.permissions[i])

        # Compute severity multiplier (alpha) for toxic/critical drifted permissions
        alpha = 1.0
        for p in drift_perms:
            if p in CRITICAL_PERMISSIONS:
                alpha = max(alpha, CRITICAL_PERMISSIONS[p])

        # Clamped Risk Score: Use trained Phase 2 Isolation Forest ML model
        ml_pred = ml_service.predict_user(user) if ml_service.is_loaded else None
        if ml_pred and ml_pred.get("model_status") == "LOADED":
            clamped_score = ml_pred["risk_score"]
        else:
            raw_score = math.floor(distance * 100.0 * alpha)
            if drift_perms and any(p in CRITICAL_PERMISSIONS for p in drift_perms):
                raw_score = max(raw_score, 75)
            clamped_score = max(0, min(100, raw_score))
        
        return clamped_score, distance, drift_perms, missing_perms, alpha

    def analyze_enterprise_topology(
        self,
        users: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """
        Processes entire roster, computes centroids, generates graph topology contracts.
        Uses Phase 2 Isolation Forest ML model for anomaly detection.
        """
        centroids = self.compute_role_centroids(users)
        
        analyzed_users = []
        for u in users:
            centroid = centroids.get(u["role"], np.zeros(self.num_perms, dtype=np.float32))
            score, dist, drift_p, missing_p, alpha = self.calculate_user_risk(u, centroid)
            
            ml_pred = ml_service.predict_user(u) if ml_service.is_loaded else None
            if ml_pred and ml_pred.get("model_status") == "LOADED":
                is_outlier = ml_pred["is_outlier"] or (len(drift_p) > 0)
                anomaly_score = ml_pred["anomaly_score"]
            else:
                is_outlier = (score >= 40) or (len(drift_p) > 0)
                anomaly_score = round(dist, 4)
            
            analyzed_users.append({
                "id": u["id"],
                "name": u["name"],
                "role": u["role"],
                "department": u["department"],
                "branch": u.get("branch", "Global HQ - New York"),
                "permissions": u["permissions"],
                "role_history": u.get("role_history", [u["role"]]),
                "risk_score": score,
                "anomaly_score": anomaly_score,
                "cosine_distance": round(dist, 4),
                "is_outlier": is_outlier,
                "drift_permissions": drift_p,
                "missing_permissions": missing_p,
                "alpha_multiplier": alpha
            })
            
        # Build node-link graph for force-graph rendering
        nodes = []
        links = []
        
        # 1. Add User Nodes
        for u in analyzed_users:
            nodes.append({
                "id": u["id"],
                "name": u["name"],
                "type": "user",
                "role": u["role"],
                "department": u["department"],
                "branch": u.get("branch", "Global HQ - New York"),
                "risk_score": u["risk_score"],
                "is_outlier": u["is_outlier"],
                "drift_count": len(u["drift_permissions"])
            })
            
        # 2. Add Permission Nodes
        active_perm_set = set()
        for u in analyzed_users:
            for p in u["permissions"]:
                active_perm_set.add(p)
                
        for p in active_perm_set:
            is_critical = p in CRITICAL_PERMISSIONS
            nodes.append({
                "id": f"perm_{p.replace(':', '_')}",
                "name": p,
                "type": "permission",
                "role": None,
                "department": None,
                "risk_score": 0,
                "is_outlier": False,
                "is_critical": is_critical
            })
            
        # 3. Add Links (User -> Permission)
        for u in analyzed_users:
            drift_set = set(u["drift_permissions"])
            for p in u["permissions"]:
                target_id = f"perm_{p.replace(':', '_')}"
                is_drift_link = p in drift_set
                links.append({
                    "source": u["id"],
                    "target": target_id,
                    "is_drift": is_drift_link
                })
                
        return {
            "users": analyzed_users,
            "topology": {
                "nodes": nodes,
                "links": links
            },
            "summary": {
                "total_users": len(analyzed_users),
                "outliers_detected": sum(1 for u in analyzed_users if u["is_outlier"]),
                "high_risk_users": sum(1 for u in analyzed_users if u["risk_score"] >= 75),
                "clean_users": sum(1 for u in analyzed_users if u["risk_score"] < 40)
            }
        }
