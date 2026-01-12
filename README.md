                                                            🛡️ CloudGuard: AI-Native IAM Governance Agent

🎯 The Vision

Modern Enterprise IT environments are scaling faster than security teams can audit them. CloudGuard is an Agentic AI solution designed to reset the economics of cloud governance by automating the transition to Least-Privilege security architectures.

Instead of manual, reactive log reviews, CloudGuard uses Generative AI to proactively analyze cloud audit logs and generate production-ready Infrastructure-as-Code (Terraform) to close security gaps.


🚀 Key Features (Agentic AI Outcomes)

Intelligent Log Parsing: Automatically identifies Cloud Provider (AWS/GCP/Azure) from raw JSON/CSV audit logs.

Gap Analysis: Uses RAG (Retrieval-Augmented Generation) to compare actual user behavior against existing permissions.

Automated Remediation: Generates context-aware Terraform HCL for immediate risk reduction.

ITSM Integration: Designed with an ITOM-first mindset, providing clear, business-focused summaries for both technical and non-technical stakeholders.


🛠️ Tech Stack

AI Engine: Google Gemini 1.5 Pro (via LangChain).

Frontend: Streamlit (Rapid Solution Prototyping).

Infrastructure: Python, Docker, AWS App Runner.

Security Logic: IAM, Okta/Zero-Trust Principles.

📦 Installation & Setup

1. Clone the Repository
Bash

git clone https://github.com/your-username/iam-governance-agent.git
cd iam-governance-agent

2. Configure Environment Variables
Create a .env file in the root directory:

Bash : GEMINI_API_KEY=your_google_gemini_api_key

3. Run via Virtual Environment
Bash: python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate
pip install -r requirements.txt
streamlit run main.py

📊 Business Value (ROI of AI)

Efficiency: Reduces IAM policy creation time from hours to seconds.

Accountability: Provides a clear audit trail of why specific permissions were suggested.

Security: Eliminates "permission creep" by enforcing zero-trust principles automatically.



LinkedIn: www.linkedin.com/in/santhosh-balaji-0b465a213 
