"""
AccessDrift Remediation & Zero-Trust Policy Synthesizer
Prunes drifted privileges, generates compliant IAM JSON & RACF policies, and writes to CPACF audit vault.
"""

from typing import Dict, Any, List
from .crypto import crypto_vault
from .engine import AnomalyEngine


def synthesize_aws_iam_policy(user_name: str, role: str, clean_permissions: List[str]) -> Dict[str, Any]:
    """
    Generates AWS IAM Least-Privilege Policy Statement JSON.
    """
    statements = []
    
    # Map high-level permission tokens to standard IAM actions
    action_map = {
        "jira:admin": "jira:*",
        "github:repo_write": "codecommit:GitPush",
        "code:review": "codecommit:PostCommentForPullRequest",
        "db:read": "rds-db:connect",
        "s3:read": "s3:GetObject",
        "slack:admin": "sns:Publish",
        "k8s:namespace_read": "eks:DescribeNodegroup",
        "finance:reports_read": "cur:DescribeReportDefinitions",
        "finance:gl_write": "financial:PostGeneralLedger",
        "stripe:billing_admin": "payments:ManageSubscription",
        "hr:employee_pii_read": "iam:GetUserDetails",
        "hr:onboarding_admin": "iam:CreateAccessKey"
    }
    
    actions = [action_map.get(p, f"accessdrift:{p}") for p in clean_permissions]
    
    statements.append({
        "Sid": f"ZeroTrustRemediated_{role.replace(' ', '')}",
        "Effect": "Allow",
        "Action": actions,
        "Resource": "*"
    })
    
    return {
        "Version": "2026-10-04",
        "Statement": statements
    }


def synthesize_racf_commands(user_id: str, removed_permissions: List[str]) -> List[str]:
    """
    Generates IBM Z RACF Mainframe CLI revocation script.
    """
    commands = []
    for p in removed_permissions:
        resource_profile = p.upper().replace(":", ".")
        commands.append(f"PERMIT {resource_profile} CLASS(FACILITY) ID({user_id.upper()}) DELETE")
    commands.append(f"SETROPTS RACLIST(FACILITY) REFRESH")
    return commands


class RemediationManager:
    """Manages privilege pruning, policy emission, and CPACF audit trail recording."""

    def __init__(self, engine: AnomalyEngine):
        self.engine = engine

    def execute_remediation(
        self,
        user_id: str,
        all_users: List[Dict[str, Any]],
        strip_drift_only: bool = True
    ) -> Dict[str, Any]:
        """
        Remediates a user's privilege creep, updates state, and logs cryptographic audit record.
        """
        target_user = next((u for u in all_users if u["id"] == user_id), None)
        if not target_user:
            raise ValueError(f"User with id '{user_id}' not found.")

        # 1. Compute current state
        centroids = self.engine.compute_role_centroids(all_users)
        centroid = centroids[target_user["role"]]
        prev_score, _, drift_perms, _, _ = self.engine.calculate_user_risk(target_user, centroid)

        if not drift_perms and strip_drift_only:
            removed = []
            new_permissions = list(target_user["permissions"])
        else:
            removed = list(drift_perms)
            new_permissions = [p for p in target_user["permissions"] if p not in drift_perms]

        # 2. Update user state
        target_user["permissions"] = new_permissions

        # 3. Recalculate post-remediation risk score
        new_centroids = self.engine.compute_role_centroids(all_users)
        new_centroid = new_centroids[target_user["role"]]
        new_score, _, remaining_drift, _, _ = self.engine.calculate_user_risk(target_user, new_centroid)

        # 4. Synthesize compliance policies
        aws_policy = synthesize_aws_iam_policy(target_user["name"], target_user["role"], new_permissions)
        racf_script = synthesize_racf_commands(target_user["id"], removed)

        # 5. Record immutable cryptographic audit block
        audit_details = {
            "user_id": target_user["id"],
            "user_name": target_user["name"],
            "role": target_user["role"],
            "removed_permissions": removed,
            "retained_permissions": new_permissions,
            "previous_risk_score": prev_score,
            "new_risk_score": new_score,
            "aws_policy_version": aws_policy["Version"]
        }
        
        audit_block = crypto_vault.record_audit_action(
            action="AUTO_REMEDIATE_PRIVILEGE_CREEP",
            actor="ZERO_TRUST_GOVERNOR",
            details=audit_details
        )

        return {
            "user_id": target_user["id"],
            "status": "SUCCESS",
            "previous_risk_score": prev_score,
            "new_risk_score": new_score,
            "removed_permissions": removed,
            "retained_permissions": new_permissions,
            "remediated_policy_json": aws_policy,
            "racf_script": racf_script,
            "audit_block_hash": audit_block["block_hash"],
            "audit_block_index": audit_block["index"],
            "crypto_mode": audit_block["crypto_mode"]
        }
