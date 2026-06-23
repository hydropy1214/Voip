#!/usr/bin/env python3
"""
Docker configuration for VoIP Security Scanner
"""

FROM python:3.11-slim

# Install system dependencies
RUN apt-get update && apt-get install -y \\
    libpcap-dev \\
    libssl-dev \\
    wireshark \\
    tshark \\
    netcat-openbsd \\
    curl \\
    jq \\
    git \\
    build-essential \\
    && rm -rf /var/lib/apt/lists/*

# Install Nuclei
RUN curl -sL https://github.com/projectdiscovery/nuclei/releases/download/v3.1.6/nuclei_3.1.6_linux_amd64.zip -o /tmp/nuclei.zip && \
    unzip -q /tmp/nuclei.zip -d /usr/local/bin/ && \
    chmod +x /usr/local/bin/nuclei && \
    rm /tmp/nuclei.zip

WORKDIR /voip-scanner

# Copy application files
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Create non-root user
RUN useradd -m -u 1000 scanner && \
    chown -R scanner:scanner /voip-scanner

USER scanner

ENTRYPOINT ["python3", "voip_scanner.py"]
CMD ["--help"]
