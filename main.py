import streamlit as st
import pandas as pd
import os
from dotenv import load_dotenv
from langchain_google_genai import ChatGoogleGenerativeAI
from langchain_core.prompts import ChatPromptTemplate
from langchain_core.output_parsers import StrOutputParser
 




# Setup Professional UI
st.set_page_config(page_title="CloudGuard AI", page_icon="🛡️", layout="wide")
st.title("🛡️ Enterprise CloudGuard: Multi-Cloud IAM Agent")

try:
    # First, try to get the key from Streamlit Cloud Secrets
    api_key = st.secrets["GEMINI_API_KEY"]
except FileNotFoundError:
    # If running locally (where st.secrets doesn't exist), load from .env
    from dotenv import load_dotenv
    load_dotenv()
    api_key = os.getenv("GEMINI_API_KEY")

# Stop the app gracefully if no key is found
if not api_key:
    st.error("❌ API Key not found! Please add GEMINI_API_KEY to Streamlit Secrets or your .env file.")
    st.stop()

llm = ChatGoogleGenerativeAI(model="gemini-2.5-flash",google_api_key=api_key, temperature=0)

# System Prompt that handles all 3 Clouds
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

Ensure the code is clean, follows HCL standards, and uses specific resource names."""

prompt = ChatPromptTemplate.from_messages([
    ("system", system_template),
    ("human", "Analyze these logs and provide a security report + Terraform:\n\n{logs}")
])

chain = prompt | llm | StrOutputParser()

uploaded_file = st.file_uploader("Upload Multi-Cloud Audit Logs (CSV/JSON)", type=["csv", "json"])

if uploaded_file:
    df = pd.read_csv(uploaded_file) if uploaded_file.name.endswith('.csv') else pd.read_json(uploaded_file)
    st.write("### 📊 Log Preview", df.head())

    if st.button("Generate Enterprise Security Policy"):
        with st.spinner("Analyzing Cloud Infrastructure..."):
            response = chain.invoke({"logs": df.to_string()})
            
            # Use columns to make it look like a dashboard
            col1, col2 = st.columns([1, 1])
            with col1:
                st.subheader("📝 Security Assessment")
                # Split the response to show text here
                st.markdown(response.split("```")[0])
            with col2:
                st.subheader("🛠️ Terraform Infrastructure")
                # Extract the code block
                if "```" in response:
                    code = response.split("```")[1].replace("hcl", "").replace("terraform", "")
                    st.code(code, language="hcl")
