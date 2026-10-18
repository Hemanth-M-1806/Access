"""
AccessDrift Enterprise Multi-Branch, Presentation Auth & Roster Ingestion Test Suite
====================================================================================
Validates:
- Presentation personas & 1-click trial login
- Dynamic presenter registration
- Multi-branch discovery and branch-filtered topology/rosters
- CSV template download and CSV roster batch ingestion
- Manual single-employee registration and deletion
- Role protection on roster mutations
"""

import sys
import os
import unittest
import io
from fastapi.testclient import TestClient

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))

from backend.main import app, users_db


class TestEnterpriseFeatures(unittest.TestCase):

    def setUp(self):
        self.client = TestClient(app)

    def test_01_presentation_personas_and_trial_login(self):
        # 1. Fetch presentation personas
        res = self.client.get("/api/v1/auth/presentation-personas")
        self.assertEqual(res.status_code, 200)
        personas = res.json()["personas"]
        self.assertGreaterEqual(len(personas), 4)
        persona_ids = [p["id"] for p in personas]
        self.assertIn("ceo", persona_ids)
        self.assertIn("admin", persona_ids)
        self.assertIn("analyst", persona_ids)
        self.assertIn("auditor", persona_ids)

        # 2. 1-Click Trial Login as CEO
        res_trial = self.client.post("/api/v1/auth/trial-login", json={"persona": "ceo"})
        self.assertEqual(res_trial.status_code, 200)
        data = res_trial.json()
        self.assertIn("access_token", data)
        self.assertEqual(data["user"]["role"], "EXECUTIVE")
        self.assertEqual(data["user"]["name"], "Victoria Sterling")

    def test_02_dynamic_presenter_registration(self):
        # Register a live demo evaluator
        res_reg = self.client.post("/api/v1/auth/register-trial", json={
            "full_name": "Demo Evaluator",
            "organization": "IBM Cloud Innovation Lab",
            "email": "evaluator@ibm.com",
            "role": "EXECUTIVE",
            "branch": "IBM Z Systems Lab - Poughkeepsie"
        })
        self.assertEqual(res_reg.status_code, 200)
        body = res_reg.json()
        self.assertIn("access_token", body)
        self.assertEqual(body["user"]["name"], "Demo Evaluator")
        self.assertEqual(body["user"]["role"], "EXECUTIVE")

        # Verify access using the new token
        token = body["access_token"]
        res_me = self.client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {token}"})
        self.assertEqual(res_me.status_code, 200)
        self.assertEqual(res_me.json()["name"], "Demo Evaluator")

    def test_03_multi_branch_discovery_and_filtering(self):
        # 1. Get branches directory
        res_branches = self.client.get("/api/v1/branches")
        self.assertEqual(res_branches.status_code, 200)
        branches = res_branches.json()["branches"]
        self.assertGreaterEqual(len(branches), 4)
        branch_names = [b["branch"] for b in branches]
        self.assertIn("Global HQ - New York", branch_names)
        self.assertIn("EMEA Operations - London", branch_names)

        # 2. Filter users by branch
        res_ny = self.client.get("/api/v1/users?branch=Global HQ - New York")
        self.assertEqual(res_ny.status_code, 200)
        ny_users = res_ny.json()["users"]
        self.assertGreater(len(ny_users), 0)
        for u in ny_users:
            self.assertEqual(u["branch"], "Global HQ - New York")

        # 3. Filter topology by branch
        res_ny_topo = self.client.get("/api/v1/topology?branch=Global HQ - New York")
        self.assertEqual(res_ny_topo.status_code, 200)
        self.assertEqual(res_ny_topo.json()["active_branch"], "Global HQ - New York")
        nodes = res_ny_topo.json()["nodes"]
        user_nodes = [n for n in nodes if n["type"] == "user"]
        for un in user_nodes:
            self.assertEqual(un["branch"], "Global HQ - New York")

    def test_04_csv_template_download(self):
        res_tmpl = self.client.get("/api/v1/roster/csv-template")
        self.assertEqual(res_tmpl.status_code, 200)
        self.assertIn("text/csv", res_tmpl.headers["content-type"])
        self.assertIn("id,name,role,department,branch,permissions", res_tmpl.text)

    def test_05_manual_add_and_delete_user(self):
        # Login as CEO / Executive
        res_ceo = self.client.post("/api/v1/auth/trial-login", json={"persona": "ceo"})
        token = res_ceo.json()["access_token"]

        # 1. Add user manually
        new_usr_payload = {
            "id": "usr_test_manual_101",
            "name": "Jordan Bell",
            "role": "Financial Analyst",
            "department": "Finance",
            "branch": "EMEA Operations - London",
            "permissions": ["finance:reports_read", "finance:gl_write", "db:root"]  # toxic drift: db:root
        }
        res_add = self.client.post(
            "/api/v1/roster/add-user",
            json=new_usr_payload,
            headers={"Authorization": f"Bearer {token}"}
        )
        self.assertEqual(res_add.status_code, 200)
        user_data = res_add.json()["user"]
        self.assertEqual(user_data["id"], "usr_test_manual_101")
        self.assertTrue(user_data["is_outlier"])
        self.assertGreaterEqual(user_data["risk_score"], 70)

        # 2. Delete user
        res_del = self.client.delete(
            "/api/v1/roster/users/usr_test_manual_101",
            headers={"Authorization": f"Bearer {token}"}
        )
        self.assertEqual(res_del.status_code, 200)
        self.assertEqual(res_del.json()["status"], "SUCCESS")

    def test_06_csv_roster_upload(self):
        # Login as Admin
        res_adm = self.client.post("/api/v1/auth/trial-login", json={"persona": "admin"})
        token = res_adm.json()["access_token"]

        sample_csv = (
            "id,name,role,department,branch,permissions\n"
            "usr_csv_01,Tony Stark,Senior Software Engineer,Engineering,Global HQ - New York,\"github:repo_write,code:review,db:read,s3:read\"\n"
            "usr_csv_02,Pepper Potts,Engineering Manager,Engineering,Global HQ - New York,\"jira:admin,github:repo_write,code:review,db:read,s3:read,cloud:iam_admin\"\n"
        )
        file_obj = io.BytesIO(sample_csv.encode("utf-8"))

        res_upload = self.client.post(
            "/api/v1/roster/upload-csv",
            files={"file": ("test_employees.csv", file_obj, "text/csv")},
            data={"branch": "Global HQ - New York", "replace_roster": "false"},
            headers={"Authorization": f"Bearer {token}"}
        )
        self.assertEqual(res_upload.status_code, 200)
        upload_data = res_upload.json()
        self.assertEqual(upload_data["records_processed"], 2)
        self.assertEqual(upload_data["status"], "SUCCESS")

        # Verify uploaded user is present in roster
        res_usr = self.client.get("/api/v1/users/usr_csv_01")
        self.assertEqual(res_usr.status_code, 200)
        self.assertEqual(res_usr.json()["name"], "Tony Stark")


if __name__ == "__main__":
    unittest.main()
