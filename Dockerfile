FROM python:3.10-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    curl \
    build-essential \
    wget \
    unzip \
    && rm -rf /var/lib/apt/lists/*

# Create a non-root user
RUN useradd -m -u 1000 reuser
USER reuser

# Create directory structure
RUN mkdir -p /home/reuser/.local/bin
ENV PATH="/home/reuser/.local/bin:${PATH}"

# Switch to root to install Ghidra (uncomment and modify as needed)
USER root

# Install Ghidra (example - adjust version as needed)
# RUN mkdir -p /opt/ghidra && \
#     wget -q https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_10.3_build/ghidra_10.3_PUBLIC_20230510.zip -O /tmp/ghidra.zip && \
#     unzip /tmp/ghidra.zip -d /opt && \
#     mv /opt/ghidra_* /opt/ghidra && \
#     rm /tmp/ghidra.zip
# 
# ENV GHIDRA_HOME=/opt/ghidra
# ENV PATH="${GHIDRA_HOME}:${PATH}"

# Switch back to non-root user
USER reuser
WORKDIR /app

# Copy project files
COPY --chown=reuser:reuser . .

# Install Python dependencies
RUN pip install --no-cache-dir --user -r requirements.txt
RUN pip install --no-cache-dir --user -e .

# Default command
ENTRYPOINT ["python", "main.py"]
