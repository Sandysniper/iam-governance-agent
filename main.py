"""
main.py
-------
CloudGuard AI — Enterprise Multi-Cloud IAM Governance Agent
Streamlit UI layer only. All business logic lives in the agent/ package.
"""

import streamlit as st
import pandas as pd
import io
import json

from agent import run_analysis
from agent.parser import (
    extract_terraform,
    extract_analysis_sections,
    format_reasoning_steps
)

# ============================================================
# PAGE CONFIGURATION
# ============================================================
st.set_page_config(
    page_title="CloudGuard AI",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

st.markdown("""
<style>
    .stButton>button { width: 100%; border-radius: 5px; height: 3em; }
    .risk-critical { color: #FF4B4B; font-weight: bold; }
    .risk-high { color: #FFA500; font-weight: bold; }
    .risk-medium { color: #FFD700; font-weight: bold; }
    .risk-low { color: #00CC44; font-weight: bold; }
    .step-box { background: #1E1E1E; padding: 10px; border-radius: 5px; margin: 5px 0; }
</style>
""", unsafe_allow_html=True)

st.title("🛡️ Enterprise CloudGuard AI")
st.caption("Multi-Cloud IAM Security Agent | Powered by LangChain ReAct + Google Gemini")

# ============================================================
# DEMO DATA — One per cloud provider to prove multi-cloud
# ============================================================

DEMO_GCP = """timestamp,user_email,service_name,method_name,resource_name,severity
2025-10-01T09:00:00Z,dev-user@company.com,storage.googleapis.com,storage.objects.get,projects/prd-01/buckets/data-raw,INFO
2025-10-01T09:05:00Z,dev-user@company.com,storage.googleapis.com,storage.objects.list,projects/prd-01/buckets/data-raw,INFO
2025-10-01T10:15:00Z,dev-user@company.com,compute.googleapis.com,compute.instances.get,projects/prd-01/zones/us-east1/instances/web-node-1,INFO
2025-10-01T10:20:00Z,dev-user@company.com,compute.googleapis.com,compute.instances.start,projects/prd-01/zones/us-east1/instances/web-node-1,INFO
2025-10-02T14:00:00Z,analyst@company.com,bigquery.googleapis.com,google.cloud.bigquery.v2.JobService.InsertJob,projects/prd-01/jobs/job-123,INFO
2025-10-02T14:10:00Z,analyst@company.com,bigquery.googleapis.com,google.cloud.bigquery.v2.TableService.GetTable,projects/prd-01/datasets/analytics/tables/users,INFO
2025-10-03T11:00:00Z,analyst@company.com,logging.googleapis.com,google.logging.v2.LoggingServiceV2.ListLogEntries,projects/prd-01,INFO
"""

DEMO_AWS = """timestamp,user_email,eventName,eventSource,requestParameters,severity
2025-10-01T09:00:00Z,dev@company.com,GetObject,s3.amazonaws.com,bucket=prod-data,INFO
2025-10-01T10:00:00Z,dev@company.com,ListBuckets,s3.amazonaws.com,,INFO
2025-10-02T14:00:00Z,admin@company.com,DescribeInstances,ec2.amazonaws.com,,INFO
2025-10-02T15:00:00Z,admin@company.com,CreateUser,iam.amazonaws.com,username=newuser,WARNING
2025-10-03T09:00:00Z,admin@company.com,AttachRolePolicy,iam.amazonaws.com,policyArn=AdministratorAccess,CRITICAL
"""

DEMO_AZURE = """timestamp,caller,operationName,resourceGroup,resourceProvider,severity
2025-10-01T09:00:00Z,ops@company.com,Microsoft.Compute/virtualMachines/read,prod-rg,Microsoft.Compute,INFO
2025-10-01T10:00:00Z,ops@company.com,Microsoft.Storage/storageAccounts/read,prod-rg,Microsoft.Storage,INFO
2025-10-02T14:00:00Z,admin@company.com,Microsoft.Authorization/roleAssignments/write,prod-rg,Microsoft.Authorization,WARNING
2025-10-02T15:00:00Z,admin@company.com,Microsoft.Compute/virtualMachines/delete,prod-rg,Microsoft.Compute,CRITICAL
"""

# ============================================================
# SESSION STATE
# ============================================================
for key in ["data", "source", "result"]:
    if key not in st.session_state:
        st.session_state[key] = None

# ============================================================
# SIDEBAR
# ============================================================
with st.sidebar:
    st.header("⚙️ Data Source")
    uploaded_file = st.file_uploader("Upload Audit Logs (CSV/JSON)", type=["csv", "json"])

    st.markdown("---")
    st.subheader("🚀 Demo Data")
    st.caption("Load provider-specific demo logs to see multi-cloud support in action.")

    col1, col2, col3 = st.columns(3)
    with col1:
        if st.button("GCP"):
            st.session_state.data = pd.read_csv(io.StringIO(DEMO_GCP))
            st.session_state.source = "GCP Demo"
            st.session_state.result = None
            st.success("GCP logs loaded!")
    with col2:
        if st.button("AWS"):
            st.session_state.data = pd.read_csv(io.StringIO(DEMO_AWS))
            st.session_state.source = "AWS Demo"
            st.session_state.result = None
            st.success("AWS logs loaded!")
    with col3:
        if st.button("Azure"):
            st.session_state.data = pd.read_csv(io.StringIO(DEMO_AZURE))
            st.session_state.source = "Azure Demo"
            st.session_state.result = None
            st.success("Azure logs loaded!")

    st.markdown("---")
    if st.button("🔄 Clear / Reset"):
        st.session_state.data = None
        st.session_state.source = None
        st.session_state.result = None
        st.rerun()

# Handle file upload
if uploaded_file:
    try:
        if uploaded_file.name.endswith(".csv"):
            st.session_state.data = pd.read_csv(uploaded_file)
        else:
            st.session_state.data = pd.read_json(uploaded_file)
        st.session_state.source = f"Uploaded: {uploaded_file.name}"
        st.session_state.result = None
    except Exception as e:
        st.error(f"Could not read file: {str(e)}")

# ============================================================
# MAIN CONTENT
# ============================================================
if st.session_state.data is None:
    st.info("👈 Upload your audit logs or load a demo dataset from the sidebar to begin.")

    # Show architecture explanation on landing
    st.markdown("---")
    st.subheader("🤖 How the Agent Works")
    st.markdown("""
    CloudGuard AI uses a **ReAct (Reasoning + Acting)** agent loop — not a simple LLM prompt.
    
    The agent autonomously decides which tool to use at each step:
    
    | Step | Tool | What it Does |
    |------|------|--------------|
    | 1 | `detect_cloud_provider` | Identifies AWS / GCP / Azure from log structure |
    | 2 | `analyze_user_behavior` | Maps what each user actually did |
    | 3 | `identify_policy_gaps` | Finds over-privileged users (POLP violations) |
    | 4 | `generate_terraform_remediation` | Writes production-ready IaC fix code |
    | 5 | `check_compliance_violations` | Maps gaps to CIS, SOC2, ISO 27001 |
    
    Unlike a simple API call, the agent **thinks between each step**, observes the result,
    and decides what to do next — just like a human security analyst would.
    """)

else:
    # Show loaded data
    st.info(f"📂 Source: **{st.session_state.source}**")
    with st.expander("📊 Log Preview", expanded=True):
        st.dataframe(st.session_state.data, use_container_width=True)
        st.caption(f"{len(st.session_state.data)} log entries loaded")

    # Analysis button
    if st.button("🚀 Run Security Analysis", type="primary"):
        st.session_state.result = None

        with st.spinner("🤖 Agent is reasoning through your logs..."):
            log_string = st.session_state.data.to_csv(index=False)
            result = run_analysis(log_string)
            st.session_state.result = result

    # Display results
    if st.session_state.result:
        result = st.session_state.result

        if result.get("error"):
            st.error(f"Analysis failed: {result['error']}")
            st.info("Check that your GOOGLE_API_KEY is set correctly and your log format is valid.")

        else:
            st.success("✅ Analysis Complete")
            st.markdown("---")

            # --- Agent Reasoning Steps ---
            with st.expander("🧠 Agent Reasoning Steps (ReAct Loop)", expanded=False):
                steps = format_reasoning_steps(result.get("steps", []))
                if steps:
                    for i, step in enumerate(steps, 1):
                        st.markdown(f"**Step {i}: {step['emoji']} `{step['tool']}`**")
                        st.caption(f"Input: {step['input_preview']}")
                        st.caption(f"Output: {step['output_preview']}")
                        st.markdown("---")
                else:
                    st.info("No intermediate steps captured.")

            # --- Main Results Layout ---
            col1, col2 = st.columns([1, 1])

            with col1:
                st.subheader("📝 Security Assessment")
                sections = extract_analysis_sections(result.get("output", ""))
                st.markdown(sections.get("raw", "No assessment generated."))

                # Compliance report
                compliance = result.get("compliance", "")
                if compliance and compliance != "Compliance check not completed.":
                    st.markdown("---")
                    st.subheader("📋 Compliance Status")
                    st.warning(compliance)

            with col2:
                st.subheader("🛠️ Terraform Remediation")
                terraform = result.get("terraform", "")
                if terraform and terraform != "No Terraform code was generated.":
                    st.code(terraform, language="hcl")
                    st.download_button(
                        label="⬇️ Download Terraform",
                        data=terraform,
                        file_name="cloudguard_remediation.tf",
                        mime="text/plain"
                    )
                else:
                    st.info("No Terraform code was generated for this log set.")