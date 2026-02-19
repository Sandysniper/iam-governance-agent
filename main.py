import streamlit as st
import pandas as pd
import os
import io
from langchain_google_genai import ChatGoogleGenerativeAI
from langchain_core.prompts import ChatPromptTemplate
from langchain_core.output_parsers import StrOutputParser

# --- 1. CONFIGURATION & SETUP ---
st.set_page_config(page_title="CloudGuard AI", page_icon="🛡️", layout="wide")

# Custom CSS to make the "Demo" button pop
st.markdown("""
<style>
    .stButton>button {
        width: 100%;
        border-radius: 5px;
        height: 3em;
    }
</style>
""", unsafe_allow_html=True)

st.title("🛡️ Enterprise CloudGuard: Multi-Cloud IAM Agent")

# Get API Key safely
api_key = os.environ.get("GOOGLE_API_KEY")
if not api_key:
    st.error("⚠️ GOOGLE_API_KEY missing! Please set it in Docker/Environment variables.")
    st.stop()

# Initialize LLM
llm = ChatGoogleGenerativeAI(
    model="gemini-2.5-flash", # Updated to the latest fast model
    google_api_key=api_key,
    temperature=0
)

# --- 2. THE DEMO DATA (Embedded directly so no extra files needed) ---
DEMO_LOGS = """timestamp,user_email,service_name,method_name,resource_name,severity
2025-10-01T09:00:00Z,dev-user@company.com,storage.googleapis.com,storage.objects.get,projects/prd-01/buckets/data-raw,INFO
2025-10-01T09:05:00Z,dev-user@company.com,storage.googleapis.com,storage.objects.list,projects/prd-01/buckets/data-raw,INFO
2025-10-01T10:15:00Z,dev-user@company.com,compute.googleapis.com,compute.instances.get,projects/prd-01/zones/us-east1/instances/web-node-1,INFO
2025-10-01T10:20:00Z,dev-user@company.com,compute.googleapis.com,compute.instances.start,projects/prd-01/zones/us-east1/instances/web-node-1,INFO
2025-10-02T14:00:00Z,dev-user@company.com,bigquery.googleapis.com,google.cloud.bigquery.v2.JobService.InsertJob,projects/prd-01/jobs/job-123,INFO
2025-10-02T14:10:00Z,dev-user@company.com,bigquery.googleapis.com,google.cloud.bigquery.v2.TableService.GetTable,projects/prd-01/datasets/analytics/tables/users,INFO
2025-10-03T11:00:00Z,dev-user@company.com,logging.googleapis.com,google.logging.v2.LoggingServiceV2.ListLogEntries,projects/prd-01,INFO
"""

# --- 3. SESSION STATE MANAGEMENT ---
if 'data' not in st.session_state:
    st.session_state.data = None
if 'source' not in st.session_state:
    st.session_state.source = None

# --- 4. SIDEBAR CONTROLS ---
with st.sidebar:
    st.header("⚙️ Data Source")
    
    # Option A: Upload File
    uploaded_file = st.file_uploader("Upload Audit Logs (CSV/JSON)", type=["csv", "json"])
    
    # Option B: Use Demo Data
    st.markdown("---")
    st.subheader("🚀 Quick Start")
    if st.button("Load Demo Data (Recruiter Mode)"):
        st.session_state.data = pd.read_csv(io.StringIO(DEMO_LOGS))
        st.session_state.source = "Demo Logs"
        st.success("Loaded Demo Data!")
    
    if st.button("Clear / Reset"):
        st.session_state.data = None
        st.session_state.source = None
        st.rerun()

# Logic to handle uploaded file taking priority if valid
if uploaded_file:
    st.session_state.data = pd.read_csv(uploaded_file) if uploaded_file.name.endswith('.csv') else pd.read_json(uploaded_file)
    st.session_state.source = "Uploaded File"

# --- 5. MAIN LOGIC ---
system_template = """You are a Senior DevSecOps Engineer specialized in Multi-Cloud Governance.
Your task is to analyze Cloud Audit Logs (AWS CloudTrail, GCP Audit, or Azure Activity Logs).

STEP 1: IDENTIFY PROVIDER
Analyze the log format. If you see 'eventName' it's AWS. If 'methodName' it's GCP. If 'operationName' it's Azure.

STEP 2: SECURITY ANALYSIS
- Summarize the user's actual behavior in 3 bullet points.
- Identify "Dangerous Gaps" (e.g., User has 'AdministratorAccess' but only uses 'S3ReadOnly').

STEP 3: IAC GENERATION
Generate production-quality Terraform code. 
- For AWS: Use `aws_iam_policy` and `aws_iam_role_policy_attachment`.
- For GCP: Use `google_project_iam_custom_role`.
- For Azure: Use `azurerm_role_definition`.

Ensure the code is clean, follows HCL standards, and uses specific resource names.
Output the analysis first, then the code in a ```hcl block."""

prompt = ChatPromptTemplate.from_messages([
    ("system", system_template),
    ("human", "Analyze these logs and provide a security report + Terraform:\n\n{logs}")
])

chain = prompt | llm | StrOutputParser()

if st.session_state.data is not None:
    st.info(f"Using Source: {st.session_state.source}")
    st.write("### 📊 Log Preview", st.session_state.data.head())

    if st.button("Generate Enterprise Security Policy", type="primary"):
        with st.spinner("Analyzing Cloud Infrastructure..."):
            response = chain.invoke({"logs": st.session_state.data.to_string()})
            
            # Layout
            col1, col2 = st.columns([1, 1])
            
            # Parse Response
            parts = response.split("```")
            analysis = parts[0]
            # Try to find the HCL/Terraform block even if the split index varies
            terraform_code = "No code generated."
            for part in parts:
                if "resource" in part or "terraform" in part or "hcl" in part:
                     # Clean up the language identifier
                    terraform_code = part.replace("hcl", "").replace("terraform", "").strip()

            with col1:
                st.subheader("📝 Security Assessment")
                st.markdown(analysis)
            
            with col2:
                st.subheader("🛠️ Terraform Infrastructure")
                st.code(terraform_code, language="hcl")
else:
    st.info("👈 Please upload a file or click 'Load Demo Data' in the sidebar to begin.")