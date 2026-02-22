"""
agent/parser.py
---------------
Handles all output parsing for CloudGuard AI.
Replaces the fragile string.split("```") approach in the original code
with proper regex-based parsing that won't break on format variations.
"""

import re
import json
from typing import Optional


def extract_terraform(text: str) -> str:
    """
    Robustly extracts Terraform/HCL code from LLM response text.
    Handles multiple code block formats and edge cases.

    Args:
        text: Raw string output from LLM or tool

    Returns:
        Cleaned Terraform code string, or a message if none found
    """
    if not text:
        return "No Terraform code generated."

    # Pattern 1: Standard markdown code blocks with hcl or terraform language tag
    pattern_tagged = r'```(?:hcl|terraform)\s*\n([\s\S]*?)```'
    matches = re.findall(pattern_tagged, text, re.IGNORECASE)
    if matches:
        # Return the largest block (most complete terraform code)
        return max(matches, key=len).strip()

    # Pattern 2: Generic code blocks (no language tag)
    pattern_generic = r'```\s*\n([\s\S]*?)```'
    matches = re.findall(pattern_generic, text)
    if matches:
        # Filter for blocks that look like Terraform
        terraform_matches = [
            m for m in matches
            if any(keyword in m for keyword in [
                "resource", "variable", "provider",
                "aws_iam", "google_project", "azurerm_role"
            ])
        ]
        if terraform_matches:
            return max(terraform_matches, key=len).strip()

    # Pattern 3: CloudGuard AI tool output (starts with the safety header)
    if "CloudGuard AI" in text and "resource" in text:
        return text.strip()

    return "No Terraform code was found in the analysis output."


def extract_analysis_sections(text: str) -> dict:
    """
    Splits the agent's final output into meaningful sections for UI display.

    Args:
        text: The agent's final output string

    Returns:
        dict with keys: summary, risk_assessment, recommendations, raw
    """
    sections = {
        "summary": "",
        "risk_assessment": "",
        "recommendations": "",
        "raw": text
    }

    if not text:
        return sections

    # Try to find executive summary section
    summary_pattern = r'(?:executive summary|summary|overview)[:\s]*([\s\S]*?)(?=\n#{1,3}|\nrisk|\nrecommend|$)'
    summary_match = re.search(summary_pattern, text, re.IGNORECASE)
    if summary_match:
        sections["summary"] = summary_match.group(1).strip()

    # Try to find risk section
    risk_pattern = r'(?:risk|gaps identified|security gaps)[:\s]*([\s\S]*?)(?=\n#{1,3}|\nrecommend|\nterraform|$)'
    risk_match = re.search(risk_pattern, text, re.IGNORECASE)
    if risk_match:
        sections["risk_assessment"] = risk_match.group(1).strip()

    # Try to find recommendations section
    rec_pattern = r'(?:recommendations|remediation steps|next steps)[:\s]*([\s\S]*?)(?=\n#{1,3}|\n```|$)'
    rec_match = re.search(rec_pattern, text, re.IGNORECASE)
    if rec_match:
        sections["recommendations"] = rec_match.group(1).strip()

    # If no sections found, use full text as summary
    if not sections["summary"] and not sections["risk_assessment"]:
        sections["summary"] = text

    return sections


def parse_gap_analysis_for_display(gap_json: str) -> Optional[dict]:
    """
    Parses the gap analysis JSON for clean UI display in Streamlit.

    Args:
        gap_json: JSON string from identify_policy_gaps tool

    Returns:
        Parsed dict or None if parsing fails
    """
    try:
        data = json.loads(gap_json)
        if data.get("status") == "success":
            return data
        return None
    except Exception:
        return None


def format_reasoning_steps(intermediate_steps: list) -> list:
    """
    Formats the agent's intermediate steps for clean display in Streamlit.
    Converts LangChain's internal step format into readable dicts.

    Args:
        intermediate_steps: List of (AgentAction, observation) tuples

    Returns:
        List of dicts with tool, input, output keys
    """
    formatted = []

    tool_emoji = {
        "detect_cloud_provider": "🔍",
        "analyze_user_behavior": "📊",
        "identify_policy_gaps": "⚠️",
        "generate_terraform_remediation": "🛠️",
        "check_compliance_violations": "📋"
    }

    for action, observation in intermediate_steps:
        tool_name = getattr(action, "tool", "unknown_tool")
        tool_input = getattr(action, "tool_input", "")

        # Truncate long inputs for display
        display_input = str(tool_input)
        if len(display_input) > 200:
            display_input = display_input[:200] + "... [truncated]"

        # Truncate long observations for display
        display_output = str(observation)
        if len(display_output) > 500:
            display_output = display_output[:500] + "... [truncated]"

        emoji = tool_emoji.get(tool_name, "🔧")

        formatted.append({
            "emoji": emoji,
            "tool": tool_name,
            "input_preview": display_input,
            "output_preview": display_output,
            "full_output": str(observation)
        })

    return formatted