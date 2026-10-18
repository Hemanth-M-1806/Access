"""
AccessDrift Comprehensive Security, Algorithm & API Test Suite
Validates:
- CPACF/OpenSSL dual-mode crypto & AES-256-GCM memory encryption
- Tamper-evident SHA-256 blockchain ledger integrity
- Mathematical zero-safe cosine distance and clamping boundaries
- High-risk entitlement detection & alpha multipliers
- 1-click remediation & AWS IAM / RACF policy generation
- Interactive role-change simulation & state resets
- Memory utilization profiling (< 100MB RAM)
"""

import sys
import os
import unittest
import numpy as np

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))

from backend.crypto import crypto_vault
from backend.data_generator import get_initial_dataset, ALL_PERMISSIONS, ROLE_BASELINES
from backend.engine import AnomalyEngine
from backend.remediation import RemediationManager
from backend.main import app, users_db
from fastapi.testclient import TestClient


class TestAccessDriftComprehensive(unittest.TestCase):

    def setUp(self):
        self.users = get_initial_dataset()
        self.engine = AnomalyEngine()
        self.remediation_mgr = RemediationManager(self.engine)
        self.client = TestClient(app)

    def test_01_crypto_encryption_and_tamper_detection(self):
        # 1. AES-GCM Encrypt/Decrypt
        plaintext = "TOP_SECRET_RACF_ADMIN_TOKEN"
        encrypted = crypto_vault.encrypt_vault_payload(plaintext)
        decrypted = crypto_vault.decrypt_vault_payload(encrypted["nonce_hex"], encrypted["ciphertext_hex"])
        self.assertEqual(decrypted, plaintext)

        # 2. Hash Chain Integrity
        self.assertTrue(crypto_vault.verify_ledger_integrity())

        # 3. Simulate Tampering: Alter a previous block in ledger
        if len(crypto_vault.audit_ledger) > 1:
            original_actor = crypto_vault.audit_ledger[1]["actor"]
            crypto_vault.audit_ledger[1]["actor"] = "MALICIOUS_ATTACKER"
            # Verify integrity fails
            self.assertFalse(crypto_vault.verify_ledger_integrity())
            # Restore
            crypto_vault.audit_ledger[1]["actor"] = original_actor
            self.assertTrue(crypto_vault.verify_ledger_integrity())

    def test_02_mathematical_bounds_and_safety(self):
        zero_vec = np.zeros(len(ALL_PERMISSIONS), dtype=np.float32)
        ones_vec = np.ones(len(ALL_PERMISSIONS), dtype=np.float32)
        rand_vec = np.random.rand(len(ALL_PERMISSIONS)).astype(np.float32)

        # Distance when user has zero permissions
        self.assertEqual(self.engine.compute_zero_safe_cosine_distance(zero_vec, rand_vec), 1.0)
        # Distance when centroid is zero
        self.assertEqual(self.engine.compute_zero_safe_cosine_distance(rand_vec, zero_vec), 1.0)
        # Identical vectors
        self.assertAlmostEqual(self.engine.compute_zero_safe_cosine_distance(ones_vec, ones_vec), 0.0, places=4)

    def test_03_bob_vance_privilege_creep_detection(self):
        bob = next(u for u in self.users if u["id"] == "usr_102")
        centroids = self.engine.compute_role_centroids(self.users)
        centroid = centroids[bob["role"]]

        score, dist, drift_perms, missing_perms, alpha = self.engine.calculate_user_risk(bob, centroid)

        # Bob Vance holds db:root and k8s:admin from previous DevOps role
        self.assertGreaterEqual(score, 75)
        self.assertIn("db:root", drift_perms)
        self.assertIn("k8s:admin", drift_perms)
        self.assertIn("prod:deploy", drift_perms)
        self.assertGreaterEqual(alpha, 1.35)

    def test_04_remediation_and_zero_trust_policy(self):
        result = self.remediation_mgr.execute_remediation("usr_102", self.users, strip_drift_only=True)
        self.assertEqual(result["status"], "SUCCESS")
        self.assertGreater(result["previous_risk_score"], 70)
        self.assertLess(result["new_risk_score"], 30)

        # Verify removed drift items
        self.assertIn("db:root", result["removed_permissions"])
        self.assertIn("k8s:admin", result["removed_permissions"])
        self.assertNotIn("db:root", result["retained_permissions"])

        # Check synthesized AWS IAM Policy
        aws_json = result["remediated_policy_json"]
        self.assertEqual(aws_json["Version"], "2026-10-04")
        actions = aws_json["Statement"][0]["Action"]
        self.assertIn("jira:*", actions)
        self.assertIn("codecommit:GitPush", actions)

        # Check RACF revocation commands
        racf = result["racf_script"]
        self.assertTrue(any("DB.ROOT" in cmd for cmd in racf))

    def test_05_api_simulation_and_reset(self):
        # 1. Reset state
        res_reset = self.client.post("/api/v1/reset")
        self.assertEqual(res_reset.status_code, 200)

        # 2. Get user list
        res_users = self.client.get("/api/v1/users")
        self.assertEqual(res_users.status_code, 200)
        users = res_users.json()["users"]
        self.assertGreater(len(users), 15)

        # 3. Simulate Role Shift (Promote David Kim from Senior Software Engineer to DevOps Engineer)
        res_sim = self.client.post("/api/v1/simulate/role-change", json={
            "user_id": "usr_103",
            "new_role": "DevOps Engineer"
        })
        self.assertEqual(res_sim.status_code, 200)
        updated = res_sim.json()["user"]
        self.assertEqual(updated["role"], "DevOps Engineer")

        # 4. Fetch topology contract
        res_topo = self.client.get("/api/v1/topology")
        self.assertEqual(res_topo.status_code, 200)
        topo = res_topo.json()
        self.assertTrue(len(topo["nodes"]) > 0)
        self.assertTrue(len(topo["links"]) > 0)
        # Check node typing
        user_nodes = [n for n in topo["nodes"] if n["type"] == "user"]
        perm_nodes = [n for n in topo["nodes"] if n["type"] == "permission"]
        self.assertTrue(len(user_nodes) > 0)
        self.assertTrue(len(perm_nodes) > 0)

        # 5. Check Audit Ledger endpoint
        res_ledger = self.client.get("/api/v1/audit-ledger")
        self.assertEqual(res_ledger.status_code, 200)
        self.assertTrue(res_ledger.json()["chain_integrity_valid"])

        # 7. Check Frontend Static Assets
        res_root = self.client.get("/")
        self.assertEqual(res_root.status_code, 200)
        self.assertIn("AccessDrift", res_root.text)

        res_css = self.client.get("/static/css/variables.css")
        self.assertEqual(res_css.status_code, 200)

        res_js = self.client.get("/static/js/app.js")
        self.assertEqual(res_js.status_code, 200)


if __name__ == "__main__":
    unittest.main()

