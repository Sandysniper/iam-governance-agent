"""
agent/tools.py
--------------
Defines all LangChain tools used by the CloudGuard AI agent.
Each tool represents one specific skill the agent can decide to use.
This is what makes it a true agent — the LLM decides which tool to call
and in what order, rather than following a hardcoded sequence.
"""

import json
import pandas as pd
from io import StringIO
from langchain.tools import tool


# ============================================================
# TOOL 1 — Cloud Provider Detector
# ============================================================

@tool
def detect_cloud_provider(log_sample: str) -> str:
    """
    Detects which cloud provider the audit logs belong to.
    ALWAYS call this tool first before any other analysis.
    Input: A sample string of the raw log content (first 500 chars is enough).
    Output: The detected provider name and instructions for next steps.
    """
    # Check for AWS CloudTrail signatures
    if any(key in log_sample for key in ["eventName", "userIdentity", "eventSource", "awsRegion"]):
        return (
            "PROVIDER: AWS CloudTrail\n"
            "Next Step: Call analyze_user_behavior with the full log data.\n"
            "AWS IAM context: Look for eventName as the action and "
            "userIdentity.userName as the principal."
        )

    # Check for GCP Audit Log signatures
    elif any(key in log_sample for key in ["methodName", "protoPayload", "service_name", "serviceName"]):
        return (
            "PROVIDER: GCP Audit Logs\n"
            "Next Step: Call analyze_user_behavior with the full log data.\n"
            "GCP IAM context: Look for methodName as the action and "
            "user_email or principalEmail as the principal."
        )

    # Check for Azure Activity Log signatures
    elif any(key in log_sample for key in ["operationName", "resourceGroup", "resourceProvider", "caller"]):
        return (
            "PROVIDER: Azure Activity Logs\n"
            "Next Step: Call analyze_user_behavior with the full log data.\n"
            "Azure IAM context: Look for operationName as the action and "
            "caller as the principal."
        )

    else:
        return (
            "PROVIDER: Unknown\n"
            "Could not detect provider from log sample.\n"
            "Inform the user that the log format is not recognized. "
            "Expected formats: AWS CloudTrail JSON, GCP Audit CSV/JSON, Azure Activity Log JSON."
        )


# ============================================================
# TOOL 2 — User Behavior Analyzer
# ============================================================

@tool
def analyze_user_behavior(log_data: str) -> str:
    """
    Analyzes the audit log data to map what each user actually did.
    Extracts the unique actions performed per user to establish a behavior baseline.
    Call this tool AFTER detect_cloud_provider.
    Input: Full log content as a string (CSV or JSON format).
    Output: JSON string mapping each user to their actual actions performed.
    """
    try:
        behavior_map = {}

        # --- Try CSV format first (your current demo data is CSV) ---
        try:
            df = pd.read_csv(StringIO(log_data))

            # Normalize column names to lowercase for safety
            df.columns = [col.strip().lower() for col in df.columns]

            # Map column names across providers
            # User column detection
            user_col = next(
                (c for c in df.columns if c in [
                    "user_email", "useremail", "username", "user_name",
                    "caller", "principal"
                ]),
                None
            )

            # Action column detection
            action_col = next(
                (c for c in df.columns if c in [
                    "method_name", "methodname", "eventname",
                    "event_name", "operationname", "operation_name", "action"
                ]),
                None
            )

            # Resource column detection
            resource_col = next(
                (c for c in df.columns if c in [
                    "resource_name", "resourcename", "resource",
                    "resourceid", "resource_id"
                ]),
                None
            )

            if user_col and action_col:
                for _, row in df.iterrows():
                    user = str(row[user_col]).strip()
                    action = str(row[action_col]).strip()
                    resource = str(row[resource_col]).strip() if resource_col else "N/A"

                    if user not in behavior_map:
                        behavior_map[user] = {"actions": set(), "resources": set()}

                    behavior_map[user]["actions"].add(action)
                    behavior_map[user]["resources"].add(resource)

                # Convert sets to lists for JSON serialization
                serializable_map = {
                    user: {
                        "actions_performed": list(data["actions"]),
                        "resources_accessed": list(data["resources"]),
                        "total_unique_actions": len(data["actions"])
                    }
                    for user, data in behavior_map.items()
                }

                return json.dumps({
                    "status": "success",
                    "format_detected": "CSV",
                    "total_users": len(serializable_map),
                    "total_log_entries": len(df),
                    "behavior_map": serializable_map
                }, indent=2)

        except Exception:
            pass  # Not CSV, try JSON below

        # --- Try JSON format ---
        try:
            logs = json.loads(log_data)

            # Handle both list of records and CloudTrail {"Records": [...]} format
            records = logs if isinstance(logs, list) else logs.get("Records", [logs])

            for record in records:
                # AWS CloudTrail format
                user = (
                    record.get("userIdentity", {}).get("userName") or
                    record.get("userIdentity", {}).get("principalId") or
                    # GCP format
                    record.get("protoPayload", {}).get("authenticationInfo", {}).get("principalEmail") or
                    record.get("user_email") or
                    # Azure format
                    record.get("caller") or
                    "unknown_user"
                )

                action = (
                    record.get("eventName") or           # AWS
                    record.get("methodName") or          # GCP
                    record.get("method_name") or         # GCP CSV
                    record.get("operationName") or       # Azure
                    "unknown_action"
                )

                resource = (
                    record.get("requestParameters", {}).get("bucketName") or
                    record.get("resource_name") or
                    record.get("resourceId") or
                    "N/A"
                )

                if user not in behavior_map:
                    behavior_map[user] = {"actions": set(), "resources": set()}

                behavior_map[user]["actions"].add(action)
                behavior_map[user]["resources"].add(resource)

            serializable_map = {
                user: {
                    "actions_performed": list(data["actions"]),
                    "resources_accessed": list(data["resources"]),
                    "total_unique_actions": len(data["actions"])
                }
                for user, data in behavior_map.items()
            }

            return json.dumps({
                "status": "success",
                "format_detected": "JSON",
                "total_users": len(serializable_map),
                "total_log_entries": len(records),
                "behavior_map": serializable_map
            }, indent=2)

        except Exception as e:
            return json.dumps({
                "status": "error",
                "message": f"Could not parse log data as CSV or JSON. Error: {str(e)}"
            })

    except Exception as e:
        return json.dumps({
            "status": "error",
            "message": f"Unexpected error in behavior analysis: {str(e)}"
        })


# ============================================================
# TOOL 3 — Policy Gap Identifier
# ============================================================

@tool
def identify_policy_gaps(behavior_analysis_json: str) -> str:
    """
    Identifies dangerous policy gaps — permissions that likely exist but were never used.
    A 'gap' is when a user performs very few unique actions, suggesting they are
    over-privileged relative to their actual work.
    Call this tool AFTER analyze_user_behavior.
    Input: The JSON string output from analyze_user_behavior.
    Output: JSON string listing all identified gaps with risk levels.
    """
    try:
        data = json.loads(behavior_analysis_json)

        if data.get("status") == "error":
            return json.dumps({
                "status": "error",
                "message": "Cannot identify gaps — behavior analysis failed. Fix that first."
            })

        behavior_map = data.get("behavior_map", {})
        gaps = []

        for user, info in behavior_map.items():
            actions = info.get("actions_performed", [])
            resources = info.get("resources_accessed", [])
            action_count = len(actions)

            # Risk scoring logic
            # In a real enterprise tool, you'd compare against actual IAM policy
            # Here we flag based on action diversity as a proxy for over-privileging
            if action_count <= 2:
                risk = "CRITICAL"
                reason = (
                    f"User performed only {action_count} unique action(s). "
                    "Extremely likely to be over-privileged. "
                    "Principle of Least Privilege severely violated."
                )
            elif action_count <= 5:
                risk = "HIGH"
                reason = (
                    f"User performed {action_count} unique actions. "
                    "Permissions likely exceed actual requirements. "
                    "Review and tighten IAM policy."
                )
            elif action_count <= 10:
                risk = "MEDIUM"
                reason = (
                    f"User performed {action_count} unique actions. "
                    "Some unused permissions may exist. Audit recommended."
                )
            else:
                risk = "LOW"
                reason = (
                    f"User performed {action_count} unique actions. "
                    "Access pattern appears reasonable. Periodic review still advised."
                )

            gaps.append({
                "user": user,
                "risk_level": risk,
                "actions_actually_used": actions,
                "resources_accessed": resources,
                "gap_reason": reason,
                "remediation_needed": risk in ["CRITICAL", "HIGH", "MEDIUM"]
            })

        # Sort by risk priority
        risk_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        gaps.sort(key=lambda x: risk_order.get(x["risk_level"], 4))

        critical_count = sum(1 for g in gaps if g["risk_level"] == "CRITICAL")
        high_count = sum(1 for g in gaps if g["risk_level"] == "HIGH")

        return json.dumps({
            "status": "success",
            "summary": {
                "total_users_analyzed": len(gaps),
                "critical_risks": critical_count,
                "high_risks": high_count,
                "immediate_action_required": critical_count + high_count
            },
            "gaps": gaps
        }, indent=2)

    except Exception as e:
        return json.dumps({
            "status": "error",
            "message": f"Gap analysis failed: {str(e)}"
        })


# ============================================================
# TOOL 4 — Terraform Remediation Generator
# ============================================================

@tool
def generate_terraform_remediation(gap_analysis_json: str) -> str:
    """
    Generates production-ready, provider-specific Terraform HCL code to
    remediate identified IAM policy gaps by enforcing least privilege.
    Call this tool AFTER identify_policy_gaps.
    Input: The JSON string output from identify_policy_gaps.
    Output: Complete Terraform HCL code with safety comments.
    Always generates code only for CRITICAL, HIGH, and MEDIUM risk users.
    """
    try:
        data = json.loads(gap_analysis_json)

        if data.get("status") == "error":
            return "Cannot generate Terraform — gap analysis failed."

        gaps = data.get("gaps", [])
        terraform_blocks = []

        # Safety header — this is important for the remediation safety concern
        header = """# ============================================================
# CloudGuard AI — Auto-Generated Least Privilege Remediation
# ============================================================
# ⚠️  SAFETY WARNING: DO NOT apply this code without review.
# 
# Required steps before applying:
#   1. Run: terraform plan
#   2. Review ALL planned changes carefully
#   3. Get approval from your security team
#   4. Apply in staging environment first
#   5. Only then apply to production
#
# Generated by CloudGuard AI IAM Governance Agent
# ============================================================\n"""

        terraform_blocks.append(header)

        for gap in gaps:
            if not gap.get("remediation_needed"):
                continue

            user = gap["user"]
            actions = gap["actions_actually_used"]
            risk = gap["risk_level"]
            safe_name = user.replace("@", "_at_").replace(".", "_").replace("-", "_")

            # Detect provider from action names
            is_gcp = any("." in a and "googleapis" not in a for a in actions) or \
                     any(a.startswith("storage.") or a.startswith("compute.") or
                         a.startswith("bigquery.") or a.startswith("logging.") for a in actions)

            is_aws = any(
                a[0].isupper() and not "." in a
                for a in actions
            )

            is_azure = any("/" in a for a in actions)

            if is_gcp or ("storage.objects" in str(actions) or "compute.instances" in str(actions)):
                # GCP Terraform
                permissions_list = "\n    ".join([f'"{a}",' for a in actions])
                block = f"""
# --- Remediation for: {user} | Risk: {risk} ---
resource "google_project_iam_custom_role" "least_privilege_{safe_name}" {{
  role_id     = "leastPrivilege_{safe_name[:30]}"
  title       = "Least Privilege Role - {user}"
  description = "Auto-generated by CloudGuard AI. Risk was {risk}. Only actual-use permissions included."
  permissions = [
    {permissions_list}
  ]
}}

resource "google_project_iam_member" "bind_{safe_name}" {{
  project = var.project_id
  role    = google_project_iam_custom_role.least_privilege_{safe_name}.name
  member  = "user:{user}"
}}
"""

            elif is_aws:
                # AWS Terraform
                actions_json = json.dumps(actions, indent=6)
                block = f"""
# --- Remediation for: {user} | Risk: {risk} ---
resource "aws_iam_policy" "least_privilege_{safe_name}" {{
  name        = "LeastPrivilege-{safe_name[:30]}"
  description = "Auto-generated by CloudGuard AI. Risk was {risk}. Only actual-use permissions included."

  policy = jsonencode({{
    Version = "2012-10-17"
    Statement = [
      {{
        Sid      = "LeastPrivilegeAccess"
        Effect   = "Allow"
        Action   = {actions_json}
        Resource = "*"
      }}
    ]
  }})
}}

resource "aws_iam_user_policy_attachment" "attach_{safe_name}" {{
  user       = "{user}"
  policy_arn = aws_iam_policy.least_privilege_{safe_name}.arn
}}
"""

            elif is_azure:
                # Azure Terraform
                actions_list = "\n      ".join([f'"{a}",' for a in actions])
                block = f"""
# --- Remediation for: {user} | Risk: {risk} ---
resource "azurerm_role_definition" "least_privilege_{safe_name}" {{
  name        = "LeastPrivilege-{safe_name[:30]}"
  scope       = var.subscription_scope
  description = "Auto-generated by CloudGuard AI. Risk was {risk}. Only actual-use permissions included."

  permissions {{
    actions     = [
      {actions_list}
    ]
    not_actions = []
  }}

  assignable_scopes = [var.subscription_scope]
}}

resource "azurerm_role_assignment" "assign_{safe_name}" {{
  scope              = var.subscription_scope
  role_definition_id = azurerm_role_definition.least_privilege_{safe_name}.role_definition_resource_id
  principal_id       = var.principal_id_{safe_name}
}}
"""
            else:
                # Fallback generic block
                block = f"""
# --- Remediation for: {user} | Risk: {risk} ---
# Provider could not be auto-detected. Review actions and apply manually:
# Actions used: {actions}
"""

            terraform_blocks.append(block)

        # Add variables block at the end
        variables_block = """
# ============================================================
# Variable Definitions (customize for your environment)
# ============================================================
variable "project_id" {
  description = "GCP Project ID"
  type        = string
}

variable "subscription_scope" {
  description = "Azure Subscription Scope"
  type        = string
  default     = "/subscriptions/YOUR_SUBSCRIPTION_ID"
}
"""
        terraform_blocks.append(variables_block)

        if len(terraform_blocks) <= 2:  # Only header and variables, no actual remediations
            return "No remediation needed — all users are LOW risk."

        return "\n".join(terraform_blocks)

    except Exception as e:
        return f"# Terraform generation failed: {str(e)}"


# ============================================================
# TOOL 5 — Compliance Checker (Bonus — makes project enterprise-grade)
# ============================================================

@tool
def check_compliance_violations(gap_analysis_json: str) -> str:
    """
    Maps identified security gaps to specific compliance framework violations.
    Checks against CIS Benchmark, SOC2, and ISO 27001 requirements.
    Call this tool AFTER identify_policy_gaps for enterprise-grade reporting.
    Input: The JSON string output from identify_policy_gaps.
    Output: A compliance violation report with framework references.
    """
    try:
        data = json.loads(gap_analysis_json)

        if data.get("status") == "error":
            return "Cannot check compliance — gap analysis failed."

        gaps = data.get("gaps", [])
        violations = []

        for gap in gaps:
            user = gap["user"]
            risk = gap["risk_level"]
            user_violations = []

            if risk in ["CRITICAL", "HIGH"]:
                user_violations.extend([
                    {
                        "framework": "CIS Benchmark",
                        "control": "CIS Control 6.8",
                        "description": "Establish and Maintain a Process for Granting Access to Enterprise Assets",
                        "status": "VIOLATED",
                        "details": f"User {user} appears to have excess permissions beyond operational need."
                    },
                    {
                        "framework": "SOC 2",
                        "control": "CC6.3",
                        "description": "Logical Access Security — Least Privilege",
                        "status": "VIOLATED",
                        "details": "Access rights not restricted to minimum necessary for job function."
                    },
                    {
                        "framework": "ISO 27001",
                        "control": "A.9.2.3",
                        "description": "Management of Privileged Access Rights",
                        "status": "VIOLATED",
                        "details": "Privileged access rights not regularly reviewed and justified."
                    }
                ])

            elif risk == "MEDIUM":
                user_violations.append({
                    "framework": "CIS Benchmark",
                    "control": "CIS Control 6.8",
                    "description": "Establish and Maintain a Process for Granting Access",
                    "status": "WARNING",
                    "details": f"User {user} has moderate access pattern. Periodic review recommended."
                })

            if user_violations:
                violations.append({
                    "user": user,
                    "risk_level": risk,
                    "compliance_violations": user_violations
                })

        summary = {
            "total_violations": sum(
                len(v["compliance_violations"]) for v in violations
            ),
            "frameworks_affected": ["CIS Benchmark", "SOC 2", "ISO 27001"],
            "users_with_violations": len(violations)
        }

        return json.dumps({
            "status": "success",
            "compliance_summary": summary,
            "violation_details": violations
        }, indent=2)

    except Exception as e:
        return json.dumps({
            "status": "error",
            "message": f"Compliance check failed: {str(e)}"
        })