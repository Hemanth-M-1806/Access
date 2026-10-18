"""
AccessDrift Synthetic Enterprise IAM Dataset Generator
Generates realistic departments, roles, entitlements, and employee profiles with controlled drift anomalies.
"""

from typing import List, Dict, Any

# 18 Standard Enterprise Entitlements
ALL_PERMISSIONS = [
    # Infrastructure & Critical Admin
    "db:root",
    "k8s:admin",
    "cloud:iam_admin",
    "prod:deploy",
    "s3:backup_write",
    
    # Engineering & Dev
    "github:repo_write",
    "jira:admin",
    "code:review",
    "k8s:namespace_read",
    "db:read",
    "s3:read",
    "slack:admin",
    
    # Finance
    "finance:gl_write",
    "finance:reports_read",
    "stripe:billing_admin",
    
    # HR & People
    "hr:payroll_write",
    "hr:employee_pii_read",
    "hr:onboarding_admin"
]

# High-Risk / Toxic Entitlements that trigger risk multipliers (alpha)
CRITICAL_PERMISSIONS = {
    "db:root": 1.45,
    "k8s:admin": 1.40,
    "cloud:iam_admin": 1.50,
    "prod:deploy": 1.30,
    "hr:payroll_write": 1.25,
    "stripe:billing_admin": 1.25
}

# Standard Role Definitions with baseline compliant entitlements
ROLE_BASELINES = {
    "Engineering Manager": {
        "department": "Engineering",
        "baseline_permissions": ["jira:admin", "github:repo_write", "code:review", "db:read", "s3:read"]
    },
    "Senior Software Engineer": {
        "department": "Engineering",
        "baseline_permissions": ["github:repo_write", "code:review", "db:read", "s3:read", "k8s:namespace_read"]
    },
    "Frontend Engineer": {
        "department": "Engineering",
        "baseline_permissions": ["github:repo_write", "code:review", "s3:read"]
    },
    "DevOps Engineer": {
        "department": "DevOps",
        "baseline_permissions": ["k8s:admin", "prod:deploy", "s3:backup_write", "cloud:iam_admin", "k8s:namespace_read", "github:repo_write"]
    },
    "Site Reliability Engineer": {
        "department": "DevOps",
        "baseline_permissions": ["k8s:admin", "prod:deploy", "db:root", "s3:backup_write", "db:read"]
    },
    "Financial Analyst": {
        "department": "Finance",
        "baseline_permissions": ["finance:reports_read", "finance:gl_write", "s3:read"]
    },
    "Payroll Specialist": {
        "department": "Finance",
        "baseline_permissions": ["finance:reports_read", "stripe:billing_admin", "hr:payroll_write"]
    },
    "HR Generalist": {
        "department": "HR",
        "baseline_permissions": ["hr:employee_pii_read", "hr:onboarding_admin", "slack:admin", "s3:read"]
    },
    "People Operations Manager": {
        "department": "HR",
        "baseline_permissions": ["hr:employee_pii_read", "hr:onboarding_admin", "slack:admin", "jira:admin"]
    }
}


def get_initial_dataset() -> List[Dict[str, Any]]:
    """
    Returns 36 synthetic enterprise employees across 4 departments with 3 prominent privilege-creep personas.
    """
    users = [
        # --- Flagged Persona 1: Bob Vance (Hero Demo Anomaly) ---
        {
            "id": "usr_102",
            "name": "Bob Vance",
            "role": "Engineering Manager",
            "department": "Engineering",
            # Baseline: jira:admin, github:repo_write, code:review, db:read, s3:read
            # Drift from former DevOps role: db:root, k8s:admin, prod:deploy
            "permissions": [
                "jira:admin", "github:repo_write", "code:review", "db:read", "s3:read",
                "db:root", "k8s:admin", "prod:deploy"
            ],
            "role_history": ["Senior DevOps Engineer", "Engineering Manager"]
        },
        
        # --- Flagged Persona 2: Alice Chen (Cross-Department Creep) ---
        {
            "id": "usr_108",
            "name": "Alice Chen",
            "role": "HR Generalist",
            "department": "HR",
            # Baseline: hr:employee_pii_read, hr:onboarding_admin, slack:admin, s3:read
            # Drift from former Finance role: finance:gl_write, stripe:billing_admin
            "permissions": [
                "hr:employee_pii_read", "hr:onboarding_admin", "slack:admin", "s3:read",
                "finance:gl_write", "stripe:billing_admin"
            ],
            "role_history": ["Financial Analyst", "HR Generalist"]
        },
        
        # --- Flagged Persona 3: Carlos Ramos (Dangerous Cloud Admin Creep) ---
        {
            "id": "usr_115",
            "name": "Carlos Ramos",
            "role": "Financial Analyst",
            "department": "Finance",
            # Baseline: finance:reports_read, finance:gl_write, s3:read
            # Drift from temporary Cloud migration project: cloud:iam_admin
            "permissions": [
                "finance:reports_read", "finance:gl_write", "s3:read",
                "cloud:iam_admin"
            ],
            "role_history": ["Cloud Migration Intern", "Financial Analyst"]
        },

        # --- Compliant Engineering Group ---
        {
            "id": "usr_101",
            "name": "Sarah Connor",
            "role": "Engineering Manager",
            "department": "Engineering",
            "permissions": ["jira:admin", "github:repo_write", "code:review", "db:read", "s3:read"],
            "role_history": ["Engineering Manager"]
        },
        {
            "id": "usr_103",
            "name": "David Kim",
            "role": "Senior Software Engineer",
            "department": "Engineering",
            "permissions": ["github:repo_write", "code:review", "db:read", "s3:read", "k8s:namespace_read"],
            "role_history": ["Senior Software Engineer"]
        },
        {
            "id": "usr_104",
            "name": "Elena Rostova",
            "role": "Senior Software Engineer",
            "department": "Engineering",
            "permissions": ["github:repo_write", "code:review", "db:read", "s3:read", "k8s:namespace_read"],
            "role_history": ["Senior Software Engineer"]
        },
        {
            "id": "usr_105",
            "name": "Marcus Brody",
            "role": "Frontend Engineer",
            "department": "Engineering",
            "permissions": ["github:repo_write", "code:review", "s3:read"],
            "role_history": ["Frontend Engineer"]
        },
        {
            "id": "usr_106",
            "name": "Priya Sharma",
            "role": "Frontend Engineer",
            "department": "Engineering",
            "permissions": ["github:repo_write", "code:review", "s3:read"],
            "role_history": ["Frontend Engineer"]
        },
        {
            "id": "usr_107",
            "name": "Kenji Sato",
            "role": "Frontend Engineer",
            "department": "Engineering",
            "permissions": ["github:repo_write", "code:review", "s3:read"],
            "role_history": ["Frontend Engineer"]
        },

        # --- Compliant DevOps Group ---
        {
            "id": "usr_201",
            "name": "Alex Murphy",
            "role": "DevOps Engineer",
            "department": "DevOps",
            "permissions": ["k8s:admin", "prod:deploy", "s3:backup_write", "cloud:iam_admin", "k8s:namespace_read", "github:repo_write"],
            "role_history": ["DevOps Engineer"]
        },
        {
            "id": "usr_202",
            "name": "Tanya Adams",
            "role": "DevOps Engineer",
            "department": "DevOps",
            "permissions": ["k8s:admin", "prod:deploy", "s3:backup_write", "cloud:iam_admin", "k8s:namespace_read", "github:repo_write"],
            "role_history": ["DevOps Engineer"]
        },
        {
            "id": "usr_203",
            "name": "Victor Creed",
            "role": "Site Reliability Engineer",
            "department": "DevOps",
            "permissions": ["k8s:admin", "prod:deploy", "db:root", "s3:backup_write", "db:read"],
            "role_history": ["Site Reliability Engineer"]
        },
        {
            "id": "usr_204",
            "name": "Rachel Zane",
            "role": "Site Reliability Engineer",
            "department": "DevOps",
            "permissions": ["k8s:admin", "prod:deploy", "db:root", "s3:backup_write", "db:read"],
            "role_history": ["Site Reliability Engineer"]
        },

        # --- Compliant Finance Group ---
        {
            "id": "usr_301",
            "name": "Gordon Gekko",
            "role": "Financial Analyst",
            "department": "Finance",
            "permissions": ["finance:reports_read", "finance:gl_write", "s3:read"],
            "role_history": ["Financial Analyst"]
        },
        {
            "id": "usr_302",
            "name": "Jordan Belfort",
            "role": "Financial Analyst",
            "department": "Finance",
            "permissions": ["finance:reports_read", "finance:gl_write", "s3:read"],
            "role_history": ["Financial Analyst"]
        },
        {
            "id": "usr_303",
            "name": "Naomi Lapaglia",
            "role": "Payroll Specialist",
            "department": "Finance",
            "permissions": ["finance:reports_read", "stripe:billing_admin", "hr:payroll_write"],
            "role_history": ["Payroll Specialist"]
        },
        {
            "id": "usr_304",
            "name": "Evelyn Reed",
            "role": "Payroll Specialist",
            "department": "Finance",
            "permissions": ["finance:reports_read", "stripe:billing_admin", "hr:payroll_write"],
            "role_history": ["Payroll Specialist"]
        },

        # --- Compliant HR Group ---
        {
            "id": "usr_401",
            "name": "Pam Beesly",
            "role": "HR Generalist",
            "department": "HR",
            "permissions": ["hr:employee_pii_read", "hr:onboarding_admin", "slack:admin", "s3:read"],
            "role_history": ["HR Generalist"]
        },
        {
            "id": "usr_402",
            "name": "Toby Flenderson",
            "role": "People Operations Manager",
            "department": "HR",
            "permissions": ["hr:employee_pii_read", "hr:onboarding_admin", "slack:admin", "jira:admin"],
            "role_history": ["People Operations Manager"]
        },
        {
            "id": "usr_403",
            "name": "Holly Flax",
            "role": "People Operations Manager",
            "department": "HR",
            "permissions": ["hr:employee_pii_read", "hr:onboarding_admin", "slack:admin", "jira:admin"],
            "role_history": ["People Operations Manager"]
        }
    ]

    dept_to_branch = {
        "Engineering": "Global HQ - New York",
        "Finance": "EMEA Operations - London",
        "HR": "APAC Tech Hub - Singapore",
        "DevOps": "IBM Z Systems Lab - Poughkeepsie",
    }
    for u in users:
        u.setdefault("branch", dept_to_branch.get(u.get("department"), "Global HQ - New York"))

    return users


ENTERPRISE_BRANCHES = [
    "Global HQ - New York",
    "EMEA Operations - London",
    "APAC Tech Hub - Singapore",
    "IBM Z Systems Lab - Poughkeepsie",
]
