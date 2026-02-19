# Use the full image (includes build-essential and curl by default)
FROM python:3.11-slim

LABEL maintainer="YourName"
LABEL description="CloudGuard AI IAM Agent"

# Set the working directory
WORKDIR /app

# Copy your requirements first (for better caching)
COPY requirements.txt .

# Install python dependencies

RUN pip install --upgrade pip && \
pip install --no-cache-dir -r requirements.txt

# Copy the rest of your application code
COPY . .

# Expose the port used by Streamlit
EXPOSE 8080

# The CORRECT command to launch Streamlit
# (This fixes the "missing ScriptRunContext" warning)
CMD ["streamlit", "run", "main.py", "--server.port=8080", "--server.address=0.0.0.0"]