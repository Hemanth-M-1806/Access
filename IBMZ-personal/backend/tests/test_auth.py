"""
AccessDrift Phase 3 Authentication & RBAC Test Suite
====================================================
Tests:
- Password hashing (PBKDF2-HMAC-SHA256)
- RFC 7519 HS256 JWT Token creation, signature verification, and expiration
- Login endpoint with valid/invalid credentials
- Identity introspection endpoint (/api/v1/auth/me)
- Role-Based Access Control (RBAC) enforcement across ADMIN, SECURITY_ANALYST, and AUDITOR
- Audit logging of authentication events into CPACF/OpenSSL hash chain ledger
"""

import sys
import os
import unittest
from fastapi.testclient import TestClient

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))

from backend.main import app
from backend.auth import (
    hash_password,
    verify_password,
    create_access_token,
    decode_access_token,
    ENTERPRISE_USERS,
)
from backend.crypto import crypto_vault


class TestPhase3Authentication(unittest.TestCase):

    def setUp(self):
        self.client = TestClient(app)

    def test_01_password_hashing_and_verification(self):
        raw_pw = "SuperSecretMainframeKey2026!"
        hashed = hash_password(raw_pw)
        self.assertNotEqual(raw_pw, hashed)
        self.assertIn(":", hashed)
        self.assertTrue(verify_password(raw_pw, hashed))
        self.assertFalse(verify_password("WrongPassword!", hashed))

    def test_02_jwt_creation_and_tamper_detection(self):
        user = ENTERPRISE_USERS["admin"]
        token = create_access_token(user, expires_in=60)
        self.assertEqual(len(token.split(".")), 3)

        payload = decode_access_token(token)
        self.assertEqual(payload["sub"], "admin")
        self.assertEqual(payload["role"], "ADMIN")

        # Simulate token tampering (modify payload)
        parts = token.split(".")
        tampered_token = f"{parts[0]}.eyJuYW1lIjoiSGFja2VyIn0.{parts[2]}"
        with self.assertRaises(Exception):
            decode_access_token(tampered_token)

    def test_03_login_endpoint(self):
        # 1. Valid Admin Login
        res_admin = self.client.post("/api/v1/auth/login", json={
            "username": "admin",
            "password": "AccessDrift@Admin2026!"
        })
        self.assertEqual(res_admin.status_code, 200)
        body = res_admin.json()
        self.assertIn("access_token", body)
        self.assertEqual(body["user"]["role"], "ADMIN")

        # 2. Invalid Credentials
        res_fail = self.client.post("/api/v1/auth/login", json={
            "username": "admin",
            "password": "WrongPassword123"
        })
        self.assertEqual(res_fail.status_code, 401)

        # 3. Unknown User
        res_unknown = self.client.post("/api/v1/auth/login", json={
            "username": "ghost_user",
            "password": "AnyPassword"
        })
        self.assertEqual(res_unknown.status_code, 401)

    def test_04_auth_me_identity_inspection(self):
        res = self.client.post("/api/v1/auth/login", json={
            "username": "analyst",
            "password": "Analyst@Drift2026!"
        })
        token = res.json()["access_token"]

        res_me = self.client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {token}"})
        self.assertEqual(res_me.status_code, 200)
        data = res_me.json()
        self.assertEqual(data["username"], "analyst")
        self.assertEqual(data["role"], "SECURITY_ANALYST")
        self.assertEqual(data["department"], "Cybersecurity Risk")

    def test_05_rbac_role_enforcement(self):
        # Get tokens for all 3 tiers
        res_admin = self.client.post("/api/v1/auth/login", json={"username": "admin", "password": "AccessDrift@Admin2026!"})
        admin_token = res_admin.json()["access_token"]

        res_analyst = self.client.post("/api/v1/auth/login", json={"username": "analyst", "password": "Analyst@Drift2026!"})
        analyst_token = res_analyst.json()["access_token"]

        res_auditor = self.client.post("/api/v1/auth/login", json={"username": "auditor", "password": "Audit@Compliance2026!"})
        auditor_token = res_auditor.json()["access_token"]

        # 1. /api/v1/remediate (Requires ADMIN)
        # Admin should succeed
        res_adm_rem = self.client.post(
            "/api/v1/remediate",
            json={"user_id": "usr_102", "strip_drift_only": True},
            headers={"Authorization": f"Bearer {admin_token}"}
        )
        self.assertEqual(res_adm_rem.status_code, 200)

        # Analyst must be FORBIDDEN (403)
        res_ana_rem = self.client.post(
            "/api/v1/remediate",
            json={"user_id": "usr_102", "strip_drift_only": True},
            headers={"Authorization": f"Bearer {analyst_token}"}
        )
        self.assertEqual(res_ana_rem.status_code, 403)

        # Auditor must be FORBIDDEN (403)
        res_aud_rem = self.client.post(
            "/api/v1/remediate",
            json={"user_id": "usr_102", "strip_drift_only": True},
            headers={"Authorization": f"Bearer {auditor_token}"}
        )
        self.assertEqual(res_aud_rem.status_code, 403)

        # 2. /api/v1/simulate/role-change (Requires ADMIN or SECURITY_ANALYST)
        res_ana_sim = self.client.post(
            "/api/v1/simulate/role-change",
            json={"user_id": "usr_103", "new_role": "DevOps Engineer"},
            headers={"Authorization": f"Bearer {analyst_token}"}
        )
        self.assertEqual(res_ana_sim.status_code, 200)

        # Auditor must be FORBIDDEN (403)
        res_aud_sim = self.client.post(
            "/api/v1/simulate/role-change",
            json={"user_id": "usr_103", "new_role": "DevOps Engineer"},
            headers={"Authorization": f"Bearer {auditor_token}"}
        )
        self.assertEqual(res_aud_sim.status_code, 403)

        # 3. /api/v1/audit-ledger (Requires ADMIN or AUDITOR)
        res_aud_ledger = self.client.get(
            "/api/v1/audit-ledger",
            headers={"Authorization": f"Bearer {auditor_token}"}
        )
        self.assertEqual(res_aud_ledger.status_code, 200)

        # Analyst must be FORBIDDEN (403)
        res_ana_ledger = self.client.get(
            "/api/v1/audit-ledger",
            headers={"Authorization": f"Bearer {analyst_token}"}
        )
        self.assertEqual(res_ana_ledger.status_code, 403)

    def test_06_audit_trail_records_auth_actions(self):
        # Trigger an auth action and verify blockchain chain integrity
        self.client.post("/api/v1/auth/login", json={"username": "admin", "password": "AccessDrift@Admin2026!"})
        self.assertTrue(crypto_vault.verify_ledger_integrity())
        
        # Check that AUTHENTICATION_SUCCESS was recorded
        actions = [b["action"] for b in crypto_vault.audit_ledger]
        self.assertIn("AUTHENTICATION_SUCCESS", actions)


if __name__ == "__main__":
    unittest.main()
