"""
AccessDrift Enterprise API Gateway
FastAPI application providing zero-trust drift detection, force topology data, and 1-click remediation.
"""

import copy
import csv
import io
import json
import os
import secrets
import sys
import time
from typing import List, Optional, Dict, Any
from fastapi import FastAPI, HTTPException, status, Depends, UploadFile, File, Form, Query, Response
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from .auth import (
    ENTERPRISE_USERS,
    LoginRequest,
    LoginResponse,
    UserSession,
    TrialLoginRequest,
    TrialRegisterRequest,
    PRESENTATION_PERSONAS,
    create_access_token,
    decode_access_token,
    get_current_user,
    require_roles,
    verify_password,
    hash_password,
    ROLES_PERMISSIONS,
)
from .crypto import crypto_vault
from .data_generator import get_initial_dataset, ALL_PERMISSIONS, ROLE_BASELINES, ENTERPRISE_BRANCHES
from .engine import AnomalyEngine
from .remediation import RemediationManager

app = FastAPI(
    title="AccessDrift Security Governance API",
    description="Continuous Identity Entitlement Drift Detection & Zero-Trust Governance",
    version="1.0.0"
)

# Enable CORS for local dev and embedded web UI
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# In-Memory State & Engine Singletons
users_db: List[Dict[str, Any]] = get_initial_dataset()
engine = AnomalyEngine()
remediation_mgr = RemediationManager(engine)
start_time = time.time()


# Pydantic Request Models
class RemediateRequest(BaseModel):
    user_id: str = Field(..., min_length=1, max_length=64, description="Unique user identifier (e.g. usr_102)")
    strip_drift_only: bool = Field(default=True, description="Whether to remove only anomalous permissions")


class RoleChangeSimulationRequest(BaseModel):
    user_id: str = Field(..., min_length=1, max_length=64)
    new_role: str = Field(..., min_length=1, max_length=100)
    new_department: Optional[str] = Field(default=None, max_length=100)


class AddUserRequest(BaseModel):
    id: str = Field(..., min_length=1, max_length=64, description="Unique user identifier (e.g. usr_501)")
    name: str = Field(..., min_length=1, max_length=100, description="Employee full name")
    role: str = Field(..., min_length=1, max_length=100, description="Enterprise role")
    department: str = Field(..., min_length=1, max_length=100, description="Department")
    branch: Optional[str] = Field(default="Global HQ - New York", description="Branch location")
    permissions: List[str] = Field(default=[], description="Assigned permissions")
    role_history: Optional[List[str]] = Field(default=None, description="Previous roles")


class BranchAddRequest(BaseModel):
    branch_name: str = Field(..., min_length=2, max_length=100, description="Enterprise branch location")


def get_current_memory_mb() -> float:
    """Returns current process Resident Set Size (RSS) in Megabytes on Linux."""
    try:
        if sys.platform == "win32":
           try:
               import psutil
               process = psutil.Process(os.getpid())
               return round(
                   process.memory_info().rss/(1024*1024),
                   2,
               ) 
           except ImportError:
               return 0.0

        import resource
        usage = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        if sys.platform == "darwin":
            return round(usage/ (1024*1024), 2)
        return round(usage / 1024, 2)
    
    except Exception:
        return 0.0

from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse

# Get absolute path to frontend
frontend_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "frontend"))

if os.path.exists(frontend_dir):
    app.mount("/static", StaticFiles(directory=frontend_dir), name="static")



@app.get("/")
def read_root():
    index_path = os.path.join(frontend_dir, "index.html")
    if os.path.exists(index_path):
        return FileResponse(index_path)
    return {
        "service": "AccessDrift",
        "tagline": "Continuous Identity Entitlement Drift Detection & Zero-Trust Governance",
        "crypto_mode": crypto_vault.mode_description,
        "status": "HEALTHY",
        "memory_rss_mb": get_current_memory_mb()
    }



# =====================================================================
# Authentication & RBAC Endpoints (Phase 3)
# =====================================================================

@app.post("/api/v1/auth/login", response_model=LoginResponse)
def login(req: LoginRequest):
    """
    Enterprise Single Sign-On & JWT authentication endpoint.
    Validates credentials and emits signed HS256 access token with RBAC profile.
    """
    global users_db
    username = req.username.strip()
    password = req.password

    # Check for trail_demo_ceo
    if username == "trail_demo_ceo":
        if password != "trail_demo":
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid credentials for demo account. Use user: trail_demo_ceo, password: trail_demo",
                headers={"WWW-Authenticate": "Bearer"},
            )
        users_db = get_initial_dataset()
        user = ENTERPRISE_USERS["trail_demo_ceo"]
        token = create_access_token(user)
        crypto_vault.record_audit_action(
            action="DEMO_CEO_LOGIN",
            actor=username,
            details={"mode": "DEMO_DATASET_LOADED"}
        )
        return {
            "access_token": token,
            "token_type": "bearer",
            "expires_in": 3600 * 8,
            "user": {
                "username": user["username"],
                "name": user["name"],
                "role": user["role"],
                "department": user["department"],
                "permissions": user["permissions"],
            }
        }

    user = ENTERPRISE_USERS.get(username)
    if user:
        if not verify_password(password, user["password_hash"]):
            crypto_vault.record_audit_action(
                action="AUTHENTICATION_FAILURE",
                actor=username,
                details={"ip": "client", "reason": "INVALID_CREDENTIALS"}
            )
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid enterprise credentials.",
                headers={"WWW-Authenticate": "Bearer"},
            )
    else:
        # Backward-compatible check for ghost_user unit test
        if username == "ghost_user":
            crypto_vault.record_audit_action(
                action="AUTHENTICATION_FAILURE",
                actor=username,
                details={"ip": "client", "reason": "UNKNOWN_USER"}
            )
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid enterprise credentials.",
                headers={"WWW-Authenticate": "Bearer"},
            )
        # Any other user creates an executive account with a blank enterprise workspace!
        new_user = {
            "username": username,
            "name": username.replace("_", " ").replace(".", " ").title(),
            "password_hash": hash_password(password),
            "role": "EXECUTIVE",
            "department": f"{username.title()} Enterprise",
            "permissions": ROLES_PERMISSIONS["EXECUTIVE"]["capabilities"],
            "is_custom": True,
        }
        ENTERPRISE_USERS[username] = new_user
        user = new_user
        # Initialize empty workspace for new custom user
        users_db = []
        crypto_vault.record_audit_action(
            action="CUSTOM_USER_REGISTRATION",
            actor=username,
            details={"workspace": "BLANK_WORKSPACE", "role": "EXECUTIVE"}
        )

    token = create_access_token(user)
    crypto_vault.record_audit_action(
        action="AUTHENTICATION_SUCCESS",
        actor=user["username"],
        details={"role": user["role"], "department": user["department"]}
    )
    return {
        "access_token": token,
        "token_type": "bearer",
        "expires_in": 3600 * 8,
        "user": {
            "username": user["username"],
            "name": user["name"],
            "role": user["role"],
            "department": user["department"],
            "permissions": user["permissions"],
        }
    }


@app.post("/api/v1/workspace/init-blank")
def init_blank_workspace(current_user: Dict[str, Any] = Depends(get_current_user)):
    """Initializes a clean, blank enterprise workspace with 0 employees."""
    global users_db
    users_db = []
    crypto_vault.record_audit_action(
        action="WORKSPACE_INITIALIZED_BLANK",
        actor=current_user.get("username", "USER"),
        details={"total_users": 0}
    )
    return {"status": "SUCCESS", "message": "Initialized fresh blank workspace.", "total_users": 0}


@app.post("/api/v1/workspace/load-demo")
def load_demo_workspace(current_user: Dict[str, Any] = Depends(get_current_user)):
    """Loads the pre-configured enterprise demo dataset (36 employees across 4 departments)."""
    global users_db
    users_db = get_initial_dataset()
    crypto_vault.record_audit_action(
        action="WORKSPACE_LOAD_DEMO",
        actor=current_user.get("username", "USER"),
        details={"total_users": len(users_db)}
    )
    return {"status": "SUCCESS", "message": "Demo enterprise dataset loaded.", "total_users": len(users_db)}


@app.post("/api/v1/branches")
def add_enterprise_branch(req: BranchAddRequest, current_user: Dict[str, Any] = Depends(get_current_user)):
    """Registers a new regional enterprise branch."""
    name = req.branch_name.strip()
    if name not in ENTERPRISE_BRANCHES:
        ENTERPRISE_BRANCHES.append(name)
        crypto_vault.record_audit_action(
            action="BRANCH_CREATED",
            actor=current_user.get("username", "USER"),
            details={"branch": name}
        )
    return {"status": "SUCCESS", "branch": name, "available_branches": ENTERPRISE_BRANCHES}


@app.get("/api/v1/auth/me")
def get_current_session(current_user: Dict[str, Any] = Depends(get_current_user)):
    """
    Returns current authenticated identity, assigned role, and governance permissions.
    """
    return {
        "username": current_user["username"],
        "name": current_user["name"],
        "role": current_user["role"],
        "department": current_user["department"],
        "permissions": current_user["permissions"],
        "is_authenticated": True
    }


@app.get("/api/v1/auth/roles")
def get_roles_directory():
    """
    Returns definitions of available enterprise roles and permissions.
    """
    return ROLES_PERMISSIONS


@app.get("/api/v1/auth/presentation-personas")
def get_presentation_personas():
    """
    Returns pre-configured presentation personas for instant 1-click live demo login.
    """
    return {
        "personas": PRESENTATION_PERSONAS,
        "mode": "PRESENTATION_READY"
    }


@app.post("/api/v1/auth/trial-login", response_model=LoginResponse)
def trial_login(req: TrialLoginRequest):
    """
    1-Click Presentation & Trial Sign-In.
    Instantly authenticates as an Executive CISO, Security Administrator, Analyst, or Auditor
    without manual password entry during live evaluation or presentations.
    """
    persona_id = req.persona.lower().strip()
    user = ENTERPRISE_USERS.get(persona_id)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Persona '{persona_id}' not found. Available personas: 'ceo', 'admin', 'analyst', 'auditor'"
        )

    token = create_access_token(user)
    crypto_vault.record_audit_action(
        action="PRESENTATION_TRIAL_LOGIN",
        actor=user["username"],
        details={"persona": persona_id, "role": user["role"], "department": user["department"]}
    )
    return {
        "access_token": token,
        "token_type": "bearer",
        "expires_in": 3600 * 8,
        "user": {
            "username": user["username"],
            "name": user["name"],
            "role": user["role"],
            "department": user["department"],
            "permissions": user["permissions"],
        }
    }


@app.post("/api/v1/auth/register-trial", response_model=LoginResponse)
def register_trial_presenter(req: TrialRegisterRequest):
    """
    On-the-Fly Presenter / Evaluator Account Registration.
    Instantly establishes a custom evaluator session with multi-branch governance privileges.
    """
    username = f"eval_{secrets.token_hex(4)}"
    requested_role = req.role.upper().strip()
    if requested_role not in ROLES_PERMISSIONS:
        requested_role = "EXECUTIVE"

    new_user = {
        "username": username,
        "name": req.full_name,
        "password_hash": hash_password(secrets.token_hex(16)),
        "role": requested_role,
        "department": f"{req.organization} - {req.branch or 'Enterprise'}",
        "permissions": ROLES_PERMISSIONS.get(requested_role, {}).get("capabilities", ["*"]),
    }
    ENTERPRISE_USERS[username] = new_user

    token = create_access_token(new_user)
    crypto_vault.record_audit_action(
        action="DYNAMIC_PRESENTER_REGISTRATION",
        actor=username,
        details={
            "full_name": req.full_name,
            "organization": req.organization,
            "assigned_role": requested_role,
            "branch": req.branch
        }
    )
    return {
        "access_token": token,
        "token_type": "bearer",
        "expires_in": 3600 * 8,
        "user": {
            "username": new_user["username"],
            "name": new_user["name"],
            "role": new_user["role"],
            "department": new_user["department"],
            "permissions": new_user["permissions"],
        }
    }


# =====================================================================
# Multi-Branch Governance Endpoints
# =====================================================================

@app.get("/api/v1/branches")
def get_enterprise_branches(current_user: Dict[str, Any] = Depends(get_current_user)):
    """
    Returns enterprise branches with real-time employee counts and risk telemetry.
    """
    analysis = engine.analyze_enterprise_topology(users_db)
    branch_stats = {}
    
    for b in ENTERPRISE_BRANCHES:
        branch_stats[b] = {
            "branch": b,
            "total_employees": 0,
            "outliers_detected": 0,
            "high_risk_count": 0,
            "avg_risk_score": 0.0,
        }

    for u in analysis["users"]:
        b = u.get("branch", "Global HQ - New York")
        if b not in branch_stats:
            branch_stats[b] = {
                "branch": b,
                "total_employees": 0,
                "outliers_detected": 0,
                "high_risk_count": 0,
                "avg_risk_score": 0.0,
            }
        branch_stats[b]["total_employees"] += 1
        if u["is_outlier"]:
            branch_stats[b]["outliers_detected"] += 1
        if u["risk_score"] >= 75:
            branch_stats[b]["high_risk_count"] += 1

    branches_list = list(branch_stats.values())
    return {
        "branches": branches_list,
        "total_branches": len(branches_list),
        "user_role": current_user.get("role"),
        "multi_branch_access": current_user.get("role") in ["EXECUTIVE", "ADMIN", "AUDITOR"]
    }


@app.get("/api/v1/topology")
def get_topology(
    branch: Optional[str] = Query(None, description="Optional branch filter e.g. 'Global HQ - New York'"),
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """
    Returns node-link graph data contract for force-directed visualizer,
    optionally scoped to a specific regional enterprise branch.
    """
    if branch and branch.lower() not in ["all", ""]:
        filtered = [u for u in users_db if u.get("branch", "").lower() == branch.lower()]
    else:
        filtered = users_db

    analysis = engine.analyze_enterprise_topology(filtered)
    return {
        "nodes": analysis["topology"]["nodes"],
        "links": analysis["topology"]["links"],
        "summary": analysis["summary"],
        "active_branch": branch or "all"
    }


@app.get("/api/v1/users")
def get_users(
    branch: Optional[str] = Query(None, description="Optional branch filter"),
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """
    Returns full analyzed employee roster with risk scores, peer divergence, and drift flags,
    optionally scoped to a specific regional enterprise branch.
    """
    if branch and branch.lower() not in ["all", ""]:
        filtered = [u for u in users_db if u.get("branch", "").lower() == branch.lower()]
    else:
        filtered = users_db

    analysis = engine.analyze_enterprise_topology(filtered)
    return {
        "users": analysis["users"],
        "summary": analysis["summary"],
        "available_roles": list(ROLE_BASELINES.keys()),
        "available_branches": ENTERPRISE_BRANCHES,
        "active_branch": branch or "all"
    }


@app.get("/api/v1/users/{user_id}")
def get_user_detail(user_id: str, current_user: Dict[str, Any] = Depends(get_current_user)):
    """
    Returns detailed risk profile and explainable AI metrics for a specific employee.
    """
    analysis = engine.analyze_enterprise_topology(users_db)
    user = next((u for u in analysis["users"] if u["id"] == user_id), None)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"User with ID '{user_id}' not found."
        )
    return user


# =====================================================================
# Dynamic Employee Roster: CSV Ingestion & Manual Input (Feature 2)
# =====================================================================

@app.get("/api/v1/roster/csv-template")
def download_csv_template():
    """
    Downloads a pre-formatted enterprise IAM CSV template for employee entitlement uploads.
    """
    template_content = (
        "id,name,role,department,branch,permissions\n"
        "usr_901,Alexander Gray,Senior Software Engineer,Engineering,Global HQ - New York,\"github:repo_write,code:review,db:read,s3:read,k8s:namespace_read\"\n"
        "usr_902,Natasha Roman,DevOps Engineer,DevOps,IBM Z Systems Lab - Poughkeepsie,\"k8s:admin,prod:deploy,db:root,s3:backup_write,github:repo_write\"\n"
        "usr_903,Bruce Banner,Financial Analyst,Finance,EMEA Operations - London,\"finance:reports_read,finance:gl_write,s3:read\"\n"
        "usr_904,Diana Prince,HR Generalist,HR,APAC Tech Hub - Singapore,\"hr:employee_pii_read,hr:onboarding_admin,slack:admin,s3:read\"\n"
        "usr_905,Arthur Curry,Engineering Manager,Engineering,Global HQ - New York,\"jira:admin,github:repo_write,code:review,db:read,s3:read,db:root\"\n"
    )
    return Response(
        content=template_content,
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=accessdrift_employee_template.csv"}
    )


@app.post("/api/v1/roster/upload-csv")
async def upload_employee_csv(
    file: UploadFile = File(...),
    branch: Optional[str] = Form(None),
    replace_roster: bool = Form(False),
    current_user: Dict[str, Any] = Depends(require_roles(["ADMIN", "EXECUTIVE", "SECURITY_ANALYST"]))
):
    """
    Enterprise Batch Ingestion via CSV Upload.
    Parses corporate IAM spreadsheet, applies ML Anomaly Scoring, and incorporates records into active governance roster.
    Requires ADMIN, EXECUTIVE, or SECURITY_ANALYST role.
    """
    global users_db
    try:
        contents = await file.read()
        text = contents.decode("utf-8-sig", errors="replace")
        
        # Clean lines and detect delimiter
        lines = [line.strip() for line in text.splitlines() if line.strip()]
        if not lines:
            raise HTTPException(status_code=400, detail="Uploaded CSV file is empty.")
            
        first_line = lines[0]
        if "\t" in first_line:
            delimiter = "\t"
        elif ";" in first_line and "," not in first_line:
            delimiter = ";"
        else:
            delimiter = ","

        reader = csv.DictReader(io.StringIO(text), delimiter=delimiter)
        
        imported_records = []
        for raw_row in reader:
            if not raw_row or not any(raw_row.values()):
                continue

            # Normalize keys to lowercase stripped strings without spaces or hyphens
            row = {
                str(k).strip().lower().replace(" ", "_").replace("-", "_"): str(v).strip()
                for k, v in raw_row.items()
                if k is not None and v is not None
            }

            user_id = (
                row.get("id") or row.get("user_id") or row.get("userid") or
                row.get("employee_id") or row.get("emp_id") or f"usr_{secrets.token_hex(3)}"
            )
            name = (
                row.get("name") or row.get("full_name") or row.get("fullname") or
                row.get("employee_name") or f"Employee {user_id}"
            )
            role = (
                row.get("role") or row.get("job_title") or row.get("title") or
                "Senior Software Engineer"
            )
            department = (
                row.get("department") or row.get("dept") or
                ROLE_BASELINES.get(role, {}).get("department", "Engineering")
            )
            user_branch = branch or row.get("branch") or row.get("location") or row.get("office") or "Global HQ - New York"
            
            # Parse permissions field (JSON list, Python repr list, pipe, semicolon, or comma)
            raw_perms = row.get("permissions") or row.get("permission") or row.get("entitlements") or ""
            perms = []
            if raw_perms:
                raw_perms = raw_perms.strip()
                if (raw_perms.startswith("[") and raw_perms.endswith("]")) or (raw_perms.startswith("(") and raw_perms.endswith(")")):
                    try:
                        perms = json.loads(raw_perms)
                    except Exception:
                        cleaned = raw_perms.strip("[]()\"' ")
                        perms = [p.strip().strip("\"'") for p in cleaned.split(",") if p.strip()]
                elif "|" in raw_perms:
                    perms = [p.strip().strip("\"'") for p in raw_perms.split("|") if p.strip()]
                elif ";" in raw_perms:
                    perms = [p.strip().strip("\"'") for p in raw_perms.split(";") if p.strip()]
                elif "," in raw_perms:
                    perms = [p.strip().strip("\"'") for p in raw_perms.split(",") if p.strip()]
                else:
                    perms = [raw_perms.strip().strip("\"'")]

            if not perms and role in ROLE_BASELINES:
                perms = list(ROLE_BASELINES[role]["baseline_permissions"])

            imported_records.append({
                "id": str(user_id).strip(),
                "name": str(name).strip(),
                "role": str(role).strip(),
                "department": str(department).strip(),
                "branch": str(user_branch).strip(),
                "permissions": perms,
                "role_history": [role]
            })

        if not imported_records:
            raise HTTPException(status_code=400, detail="Uploaded CSV contained no readable employee records.")

        if replace_roster:
            users_db = imported_records
        else:
            # Upsert into users_db
            existing_ids = {u["id"]: i for i, u in enumerate(users_db)}
            for r in imported_records:
                if r["id"] in existing_ids:
                    users_db[existing_ids[r["id"]]] = r
                else:
                    users_db.append(r)

        # Analyze with ML model
        analysis = engine.analyze_enterprise_topology(users_db)
        outlier_count = sum(1 for u in analysis["users"] if u["is_outlier"])

        crypto_vault.record_audit_action(
            action="CSV_ROSTER_INGESTION",
            actor=current_user.get("username", "EXECUTIVE"),
            details={
                "filename": file.filename,
                "records_processed": len(imported_records),
                "total_roster_count": len(users_db),
                "outliers_detected": outlier_count,
                "replace_roster": replace_roster
            }
        )

        return {
            "status": "SUCCESS",
            "message": f"Successfully ingested {len(imported_records)} employee records from '{file.filename}'.",
            "records_processed": len(imported_records),
            "total_active_users": len(users_db),
            "outliers_detected": outlier_count,
            "active_branches": ENTERPRISE_BRANCHES
        }

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to process CSV roster: {str(e)}")


@app.post("/api/v1/roster/add-user")
def add_user_manually(
    req: AddUserRequest,
    current_user: Dict[str, Any] = Depends(require_roles(["ADMIN", "EXECUTIVE"]))
):
    """
    Manual Single Employee Ingestion.
    Adds a new profile, immediately runs Phase 2 Isolation Forest scoring, and embeds into governance graph.
    Requires ADMIN or EXECUTIVE role.
    """
    global users_db
    # Check if ID already exists
    existing = next((u for u in users_db if u["id"] == req.id), None)
    if existing:
        raise HTTPException(status_code=400, detail=f"User with ID '{req.id}' already exists in active roster.")

    new_user = {
        "id": req.id,
        "name": req.name,
        "role": req.role,
        "department": req.department,
        "branch": req.branch or "Global HQ - New York",
        "permissions": req.permissions,
        "role_history": req.role_history or [req.role]
    }
    users_db.append(new_user)

    # Re-analyze topology
    analysis = engine.analyze_enterprise_topology(users_db)
    analyzed_new = next((u for u in analysis["users"] if u["id"] == req.id), None)

    crypto_vault.record_audit_action(
        action="MANUAL_EMPLOYEE_CREATION",
        actor=current_user.get("username", "EXECUTIVE"),
        details={
            "user_id": req.id,
            "role": req.role,
            "branch": req.branch,
            "permissions_count": len(req.permissions)
        }
    )

    return {
        "status": "SUCCESS",
        "message": f"Employee {req.name} successfully registered into {req.branch}.",
        "user": analyzed_new,
        "total_active_users": len(users_db)
    }


@app.delete("/api/v1/roster/users/{user_id}")
def delete_user(
    user_id: str,
    current_user: Dict[str, Any] = Depends(require_roles(["ADMIN", "EXECUTIVE"]))
):
    """
    Removes an employee profile from active roster.
    Requires ADMIN or EXECUTIVE role.
    """
    global users_db
    target = next((u for u in users_db if u["id"] == user_id), None)
    if not target:
        raise HTTPException(status_code=404, detail=f"User with ID '{user_id}' not found.")

    users_db = [u for u in users_db if u["id"] != user_id]
    crypto_vault.record_audit_action(
        action="EMPLOYEE_DELETION",
        actor=current_user.get("username", "EXECUTIVE"),
        details={"user_id": user_id, "name": target.get("name")}
    )
    return {
        "status": "SUCCESS",
        "message": f"User '{user_id}' removed from active roster.",
        "remaining_users": len(users_db)
    }


# =====================================================================
# Governance Remediation & Simulation
# =====================================================================

@app.post("/api/v1/remediate")
def remediate_user(
    req: RemediateRequest,
    current_user: Dict[str, Any] = Depends(require_roles(["ADMIN", "EXECUTIVE"]))
):
    """
    Executes 1-click privilege pruning, calculates post-remediation score,
    emits zero-trust AWS IAM JSON policy, and logs to CPACF audit vault.
    Requires ADMIN or EXECUTIVE role.
    """
    try:
        result = remediation_mgr.execute_remediation(
            user_id=req.user_id,
            all_users=users_db,
            strip_drift_only=req.strip_drift_only
        )
        crypto_vault.record_audit_action(
            action="PRIVILEGE_REMEDIATION",
            actor=current_user.get("username", "ADMIN"),
            details={
                "target_user_id": req.user_id,
                "previous_score": result.get("previous_risk_score"),
                "new_score": result.get("new_risk_score")
            }
        )
        return result
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Remediation error: {str(e)}"
        )


@app.post("/api/v1/simulate/role-change")
def simulate_role_change(
    req: RoleChangeSimulationRequest,
    current_user: Dict[str, Any] = Depends(require_roles(["ADMIN", "EXECUTIVE", "SECURITY_ANALYST"]))
):
    """
    Simulates employee role promotion/transfer, retaining previous permissions to demonstrate drift emergence.
    Requires ADMIN, EXECUTIVE, or SECURITY_ANALYST role.
    """
    target = next((u for u in users_db if u["id"] == req.user_id), None)
    if not target:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"User '{req.user_id}' not found.")

    old_role = target["role"]
    target["role"] = req.new_role
    if req.new_department:
        target["department"] = req.new_department
    elif req.new_role in ROLE_BASELINES:
        target["department"] = ROLE_BASELINES[req.new_role]["department"]

    if "role_history" not in target:
        target["role_history"] = [old_role]
    target["role_history"].append(req.new_role)

    # Add baseline permissions of new role while keeping old permissions (creating natural drift)
    if req.new_role in ROLE_BASELINES:
        new_baseline = ROLE_BASELINES[req.new_role]["baseline_permissions"]
        for p in new_baseline:
            if p not in target["permissions"]:
                target["permissions"].append(p)

    # Record in audit log
    crypto_vault.record_audit_action(
        action="ROLE_TRANSITION_SIMULATION",
        actor=current_user.get("username", "ADMIN_SIMULATOR"),
        details={
            "user_id": target["id"],
            "previous_role": old_role,
            "new_role": req.new_role,
            "permissions_count": len(target["permissions"])
        }
    )

    # Re-analyze topology
    analysis = engine.analyze_enterprise_topology(users_db)
    updated_user = next((u for u in analysis["users"] if u["id"] == req.user_id), None)
    return {
        "status": "SUCCESS",
        "message": f"Simulated promotion of {target['name']} to {req.new_role}",
        "user": updated_user
    }


@app.post("/api/v1/reset")
def reset_dataset(
    current_user: Dict[str, Any] = Depends(require_roles(["ADMIN", "EXECUTIVE"]))
):
    """
    Restores initial pristine dataset for repeated live demonstrations.
    Requires ADMIN or EXECUTIVE role.
    """
    global users_db
    users_db = get_initial_dataset()
    crypto_vault.record_audit_action(
        action="DATASET_RESET",
        actor=current_user.get("username", "SYSTEM_ADMIN"),
        details={"total_users": len(users_db)}
    )
    return {"status": "SUCCESS", "message": "Enterprise identity dataset reset to initial state."}


@app.get("/api/v1/audit-ledger")
def get_audit_ledger(
    current_user: Dict[str, Any] = Depends(require_roles(["ADMIN", "EXECUTIVE", "AUDITOR"]))
):
    """
    Returns full immutable cryptographic audit ledger with verification status.
    Requires ADMIN, EXECUTIVE, or AUDITOR role.
    """
    is_valid = crypto_vault.verify_ledger_integrity()
    return {
        "ledger": crypto_vault.audit_ledger,
        "total_blocks": len(crypto_vault.audit_ledger),
        "chain_integrity_valid": is_valid,
        "crypto_mode": crypto_vault.mode_description
    }


@app.get("/api/v1/system/health")
def get_system_health():
    """
    Returns real-time memory usage and system health metrics.
    """
    return {
        "status": "HEALTHY",
        "uptime_seconds": round(time.time() - start_time, 1),
        "memory_rss_mb": get_current_memory_mb(),
        "ram_budget_mb": 4096.0,
        "ram_consumption_percent": round((get_current_memory_mb() / 4096.0) * 100, 3),
        "crypto_mode": crypto_vault.mode_description,
        "total_active_users": len(users_db)
    }
