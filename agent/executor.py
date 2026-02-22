"""
agent/executor.py
-----------------
Builds and runs the CloudGuard AI agent.
This is where the LLM, tools, and reasoning loop are assembled together.
The AgentExecutor is what makes this a true agent — it runs a
Think → Act → Observe loop until the task is complete.
"""



import os
from dotenv import load_dotenv
load_dotenv()

from langchain_google_genai import ChatGoogleGenerativeAI
from langchain.agents import AgentExecutor, create_react_agent
from langchain import hub


from agent.tools import (
    detect_cloud_provider,
    analyze_user_behavior,
    identify_policy_gaps,
    generate_terraform_remediation,
    check_compliance_violations
)


def build_agent() -> AgentExecutor:
    """
    Assembles the CloudGuard AI agent with all tools attached.
    Uses the ReAct (Reasoning + Acting) framework — the agent thinks
    about what to do, picks a tool, observes the result, then thinks again.
    Returns a ready-to-use AgentExecutor.
    """
    api_key = os.environ.get("GOOGLE_API_KEY")
    if not api_key:
        raise ValueError("GOOGLE_API_KEY environment variable is not set.")

    # Initialize the LLM
    llm = ChatGoogleGenerativeAI(
        model="gemini-2.5-flash",
        google_api_key=api_key,
        temperature=0  # Zero temp = deterministic, consistent security analysis
    )

    # All tools the agent can choose from
    tools = [
        detect_cloud_provider,
        analyze_user_behavior,
        identify_policy_gaps,
        generate_terraform_remediation,
        check_compliance_violations
    ]

    # ReAct prompt — this is the reasoning framework
    # It instructs the agent to think before acting and observe after
    prompt = hub.pull("hwchase17/react")

    # Create the agent (the reasoning brain)
    agent = create_react_agent(
        llm=llm,
        tools=tools,
        prompt=prompt
    )

    # Wrap in executor (the engine that runs the loop)
    agent_executor = AgentExecutor(
        agent=agent,
        tools=tools,
        verbose=True,           # Shows reasoning steps in terminal
        max_iterations=12,      # Prevents infinite loops
        handle_parsing_errors=True,  # Gracefully handles LLM formatting issues
        return_intermediate_steps=True  # Captures each tool call for UI display
    )

    return agent_executor


def run_analysis(log_data: str) -> dict:
    """
    Runs the full CloudGuard security analysis on provided log data.
    The agent will autonomously decide the order of tool calls.

    Args:
        log_data: Raw log content as string (CSV or JSON format)

    Returns:
        dict with keys:
            - output: Final analysis text from the agent
            - steps: List of intermediate reasoning steps
            - terraform: Extracted Terraform code
            - error: Error message if something went wrong (None if success)
    """
    try:
        agent_executor = build_agent()

        # This is the master prompt that kicks off the agent's reasoning
        # Notice we don't tell it HOW to do things — it figures that out
        master_prompt = f"""
You are CloudGuard AI, an enterprise cloud security agent specialized in IAM governance.

Analyze the following cloud audit logs by following these steps IN ORDER:

STEP 1: Call detect_cloud_provider with the first 500 characters of the log data
         to identify if these are AWS, GCP, or Azure logs.

STEP 2: Call analyze_user_behavior with the FULL log data to map what each
         user actually did.

STEP 3: Call identify_policy_gaps with the output from Step 2 to find
         dangerous over-privileged users.

STEP 4: Call generate_terraform_remediation with the output from Step 3
         to create production-ready fix code.

STEP 5: Call check_compliance_violations with the output from Step 3
         to identify which compliance frameworks are violated.

STEP 6: Write a final executive summary that includes:
         - Cloud provider detected
         - Number of users analyzed
         - Risk breakdown (CRITICAL/HIGH/MEDIUM/LOW)
         - Top 3 most urgent remediations needed
         - Compliance frameworks affected

Here are the logs to analyze:

{log_data}
"""

        result = agent_executor.invoke({"input": master_prompt})

        # Extract terraform code from intermediate steps
        terraform_code = _extract_terraform_from_steps(result)

        # Extract compliance report from intermediate steps
        compliance_report = _extract_compliance_from_steps(result)

        return {
            "output": result.get("output", "No output generated."),
            "steps": result.get("intermediate_steps", []),
            "terraform": terraform_code,
            "compliance": compliance_report,
            "error": None
        }

    except Exception as e:
        return {
            "output": None,
            "steps": [],
            "terraform": None,
            "compliance": None,
            "error": str(e)
        }


def _extract_terraform_from_steps(result: dict) -> str:
    """
    Extracts Terraform code from the agent's intermediate steps.
    Looks for the output of the generate_terraform_remediation tool call.
    """
    steps = result.get("intermediate_steps", [])

    for action, observation in steps:
        tool_name = getattr(action, "tool", "")
        if tool_name == "generate_terraform_remediation":
            if isinstance(observation, str) and len(observation) > 50:
                return observation

    # Fallback — try to extract from final output using regex
    import re
    output = result.get("output", "")
    pattern = r'```(?:hcl|terraform)?\s*([\s\S]*?)```'
    matches = re.findall(pattern, output)
    if matches:
        return max(matches, key=len).strip()

    return "No Terraform code was generated."


def _extract_compliance_from_steps(result: dict) -> str:
    """
    Extracts the compliance report from the agent's intermediate steps.
    Looks for the output of the check_compliance_violations tool call.
    """
    import json

    steps = result.get("intermediate_steps", [])

    for action, observation in steps:
        tool_name = getattr(action, "tool", "")
        if tool_name == "check_compliance_violations":
            try:
                data = json.loads(observation)
                if data.get("status") == "success":
                    summary = data.get("compliance_summary", {})
                    return (
                        f"**Compliance Summary**\n"
                        f"- Total Violations: {summary.get('total_violations', 0)}\n"
                        f"- Users Affected: {summary.get('users_with_violations', 0)}\n"
                        f"- Frameworks: {', '.join(summary.get('frameworks_affected', []))}"
                    )
            except Exception:
                return observation

    return "Compliance check not completed."