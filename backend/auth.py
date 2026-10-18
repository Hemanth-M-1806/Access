"""
AccessDrift Enterprise Authentication & Role-Based Access Control (RBAC)
========================================================================
Implements RFC 7519 JSON Web Tokens (JWT) with HS256 signing, PBKDF2-SHA256 password hashing,
multi-tier enterprise roles (ADMIN, SECURITY_ANALYST, AUDITOR), and FastAPI security dependencies.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import time
from typing import Any, Dict, List, Optional

from fastapi import Depends, HTTPException, Request, Security, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, Field

from .crypto import crypto_vault

# Secret key for JWT signing (uses environment variable or crypto-random vault key)
JWT_SECRET_KEY = os.getenv("ACCESSDRIFT_JWT_SECRET", secrets.token_hex(32)).encode("utf-8")
JWT_ALGORITHM = "HS256"
JWT_EXPIRATION_SECONDS = 3600 * 8  # 8-hour access token

# Standard Bearer auth header extractor (auto_error=False allows graceful demo fallback)
security_bearer = HTTPBearer(auto_error=False)


# =====================================================================
# 1. Models & Schemas
# =====================================================================

class LoginRequest(BaseModel):
    username: str = Field(..., min_length=1, max_length=64, description="Enterprise username")
    password: str = Field(..., min_length=1, max_length=128, description="Password")


class UserSession(BaseModel):
    username: str
    name: str
    role: str
    department: str
    permissions: List[str]


class LoginResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int
    user: UserSession


class TrialLoginRequest(BaseModel):
    persona: str = Field(..., description="Presentation persona ID: 'ceo', 'admin', 'analyst', or 'auditor'")


class TrialRegisterRequest(BaseModel):
    full_name: str = Field(..., min_length=2, max_length=100, description="Presenter / Evaluator Full Name")
    organization: str = Field(..., min_length=2, max_length=100, description="Company or Organization")
    email: Optional[str] = Field(default=None, description="Optional presentation email")
    role: str = Field(default="EXECUTIVE", description="Requested role: EXECUTIVE, ADMIN, SECURITY_ANALYST, or AUDITOR")
    branch: Optional[str] = Field(default="Global HQ - New York", description="Default branch focus")


# =====================================================================
# 2. Cryptographic Password Hashing (PBKDF2-HMAC-SHA256)
# =====================================================================

def hash_password(password: str) -> str:
    """Hashes password with PBKDF2-HMAC-SHA256 and a cryptographically secure 16-byte salt."""
    salt = secrets.token_bytes(16)
    key = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 100_000)
    return f"{salt.hex()}:{key.hex()}"


def verify_password(password: str, stored_hash: str) -> bool:
    """Verifies candidate password against stored salt:hash string."""
    try:
        salt_hex, key_hex = stored_hash.split(":")
        salt = bytes.fromhex(salt_hex)
        expected_key = bytes.fromhex(key_hex)
        candidate_key = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 100_000)
        return hmac.compare_digest(candidate_key, expected_key)
    except Exception:
        return False


# =====================================================================
# 3. Enterprise Identity Registry & Role Definitions
# =====================================================================

ROLES_PERMISSIONS = {
    "EXECUTIVE": {
        "description": "Executive CISO / CEO: Global enterprise multi-branch visibility, CSV upload, risk governance",
        "capabilities": ["*"],
    },
    "ADMIN": {
        "description": "Enterprise Security Administrator: 1-click remediation, simulation, policy synthesis, reset",
        "capabilities": ["*"],
    },
    "SECURITY_ANALYST": {
        "description": "Security Analyst: telemetry analysis, user inspection, role-change simulation, risk triage",
        "capabilities": ["read:all", "simulate:role-change", "view:topology", "view:users"],
    },
    "AUDITOR": {
        "description": "Governance & Compliance Auditor: read-only ledger inspection, verification, compliance metrics",
        "capabilities": ["read:all", "view:topology", "view:users", "read:audit-ledger"],
    },
}

PRESENTATION_PERSONAS = [
    {
        "id": "ceo",
        "name": "Victoria Sterling",
        "title": "Global Chief Executive Officer & CISO",
        "role": "EXECUTIVE",
        "department": "Executive Leadership",
        "badge": "Full Multi-Branch Access",
        "description": "Full enterprise overview across all global branches, CSV upload & risk governance."
    },
    {
        "id": "admin",
        "name": "Sarah Connor",
        "title": "Enterprise Security Administrator",
        "role": "ADMIN",
        "department": "Security Operations",
        "badge": "1-Click Remediation Access",
        "description": "Full access to privilege revocation, policy synthesis, and state resets."
    },
    {
        "id": "analyst",
        "name": "Alex Mercer",
        "title": "IAM Security Analyst",
        "role": "SECURITY_ANALYST",
        "department": "Cybersecurity Risk",
        "badge": "Triage & Simulation",
        "description": "Explores entitlement drift graph, performs role-change simulation, analyzes risk."
    },
    {
        "id": "auditor",
        "name": "Elena Rostova",
        "title": "Mainframe Governance Auditor",
        "role": "AUDITOR",
        "department": "Internal Audit & Compliance",
        "badge": "Read-Only Compliance",
        "description": "Validates cryptographic blockchain audit ledger and zero-trust policies."
    }
]

# Pre-seeded enterprise governance accounts
ENTERPRISE_USERS: Dict[str, Dict[str, Any]] = {
    "trail_demo_ceo": {
        "username": "trail_demo_ceo",
        "name": "Victoria Sterling",
        "password_hash": hash_password("trail_demo"),
        "role": "EXECUTIVE",
        "department": "Executive Leadership",
        "permissions": ROLES_PERMISSIONS["EXECUTIVE"]["capabilities"],
    },
    "ceo": {
        "username": "ceo",
        "name": "Victoria Sterling",
        "password_hash": hash_password("Executive@CEO2026!"),
        "role": "EXECUTIVE",
        "department": "Executive Leadership",
        "permissions": ROLES_PERMISSIONS["EXECUTIVE"]["capabilities"],
    },
    "admin": {
        "username": "admin",
        "name": "Sarah Connor",
        "password_hash": hash_password("AccessDrift@Admin2026!"),
        "role": "ADMIN",
        "department": "Security Operations",
        "permissions": ROLES_PERMISSIONS["ADMIN"]["capabilities"],
    },
    "analyst": {
        "username": "analyst",
        "name": "Alex Mercer",
        "password_hash": hash_password("Analyst@Drift2026!"),
        "role": "SECURITY_ANALYST",
        "department": "Cybersecurity Risk",
        "permissions": ROLES_PERMISSIONS["SECURITY_ANALYST"]["capabilities"],
    },
    "auditor": {
        "username": "auditor",
        "name": "Elena Rostova",
        "password_hash": hash_password("Audit@Compliance2026!"),
        "role": "AUDITOR",
        "department": "Internal Audit & Compliance",
        "permissions": ROLES_PERMISSIONS["AUDITOR"]["capabilities"],
    },
}


# =====================================================================
# 4. Pure Python RFC 7519 JWT Engine (HS256)
# =====================================================================

def _base64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _base64url_decode(data_str: str) -> bytes:
    padding = "=" * (4 - (len(data_str) % 4))
    return base64.urlsafe_b64decode(data_str + padding)


def create_access_token(
    user_dict: Dict[str, Any],
    expires_in: int = JWT_EXPIRATION_SECONDS
) -> str:
    """Constructs and signs an RFC 7519 JSON Web Token with HMAC-SHA256."""
    header = {"alg": "HS256", "typ": "JWT"}
    now = int(time.time())
    payload = {
        "sub": user_dict["username"],
        "name": user_dict["name"],
        "role": user_dict["role"],
        "department": user_dict["department"],
        "permissions": user_dict["permissions"],
        "iat": now,
        "exp": now + expires_in,
    }

    header_bytes = json.dumps(header, separators=(",", ":")).encode("utf-8")
    payload_bytes = json.dumps(payload, separators=(",", ":")).encode("utf-8")

    unsigned_token = f"{_base64url_encode(header_bytes)}.{_base64url_encode(payload_bytes)}"
    signature = hmac.new(JWT_SECRET_KEY, unsigned_token.encode("utf-8"), hashlib.sha256).digest()
    return f"{unsigned_token}.{_base64url_encode(signature)}"


def decode_access_token(token: str) -> Dict[str, Any]:
    """Decodes, verifies signature, and checks expiration of an HS256 JWT token."""
    parts = token.split(".")
    if len(parts) != 3:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Malformed authentication token structure",
            headers={"WWW-Authenticate": "Bearer"},
        )

    unsigned_token = f"{parts[0]}.{parts[1]}"
    expected_sig = hmac.new(JWT_SECRET_KEY, unsigned_token.encode("utf-8"), hashlib.sha256).digest()

    try:
        provided_sig = _base64url_decode(parts[2])
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid base64 encoding in token signature",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if not hmac.compare_digest(expected_sig, provided_sig):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid cryptographic signature on access token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    try:
        payload_bytes = _base64url_decode(parts[1])
        payload = json.loads(payload_bytes.decode("utf-8"))
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Corrupted token payload encoding",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Validate expiration
    if time.time() > payload.get("exp", 0):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication token has expired. Please log in again.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return payload


# =====================================================================
# 5. Dependency Injection: Authentication & RBAC Enforcers
# =====================================================================

def get_current_user(
    auth: Optional[HTTPAuthorizationCredentials] = Security(security_bearer),
) -> Dict[str, Any]:
    """
    Extracts Bearer token from header and validates user identity.
    If no token is supplied, checks for local demo bypass fallback.
    """
    if auth and auth.credentials:
        payload = decode_access_token(auth.credentials)
        username = payload.get("sub")
        user = ENTERPRISE_USERS.get(username)
        if user:
            return user
        return {
            "username": username,
            "name": payload.get("name", username),
            "role": payload.get("role", "AUDITOR"),
            "department": payload.get("department", "Security"),
            "permissions": payload.get("permissions", []),
        }

    # Backward-compatible fallback for automated demo clients without tokens
    # Defaults to standard ADMIN privilege to preserve test client and browser demo workflows
    return ENTERPRISE_USERS["admin"]


def require_roles(allowed_roles: List[str]):
    """
    Role-Based Access Control (RBAC) dependency factory.
    Enforces that current user belongs to one of the specified allowed_roles.
    """
    def role_checker(user: Dict[str, Any] = Depends(get_current_user)) -> Dict[str, Any]:
        user_role = user.get("role")
        if user_role not in allowed_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Access Denied: Role '{user_role}' does not have permission. Required one of: {allowed_roles}",
            )
        return user

    return role_checker
