#!/bin/bash
# VoIP Security Framework Setup Script

set -euo pipefail

echo "========================================"
echo "VoIP Security Framework Installer"
echo "========================================"

# Check if running as root for tool installation
if [[ "$1" == "--install" ]]; then
    if [[ $EUID -ne 0 ]]; then
        echo "[!] Root privileges required for --install"
        exit 1
    fi
    echo "[*] Installing system dependencies..."
    apt-get update -qq
    apt-get install -y -qq \
        python3-dev \
        libpcap-dev \
        libssl-dev \
        wireshark \
        tshark \
        netcat-openbsd \
        curl \
        jq \
        git \
        build-essential
    
    echo "[*] Installing Nuclei vulnerability scanner..."
    NVER="3.1.6"
    curl -sL "https://github.com/projectdiscovery/nuclei/releases/download/v${NVER}/nuclei_${NVER}_linux_amd64.zip" -o /tmp/nuclei.zip
    unzip -q /tmp/nuclei.zip -d /usr/local/bin/
    chmod +x /usr/local/bin/nuclei
    rm /tmp/nuclei.zip
    
    echo "[+] System dependencies installed"
fi

echo "[*] Setting up Python virtual environment..."
if [[ ! -d "venv" ]]; then
    python3 -m venv venv
fi
source venv/bin/activate

echo "[*] Installing Python dependencies..."
pip install --upgrade pip setuptools wheel
pip install -r requirements.txt

echo "[*] Creating directories..."
mkdir -p logs reports results config/custom

echo "[*] Setting permissions..."
chmod +x voip_scanner.py
chmod +x modules/**/*.py

echo "[*] Generating configuration templates..."
if [[ ! -f "config/profiles.yaml" ]]; then
    cp config/profiles.yaml.example config/profiles.yaml 2>/dev/null || echo "[!] Create config/profiles.yaml manually"
fi

echo ""
echo "========================================"
echo "[+] Setup complete!"
echo "========================================"
echo ""
echo "Next steps:"
echo "1. Activate virtual environment: source venv/bin/activate"
echo "2. Configure targets: edit config/profiles.yaml"
echo "3. Run scanner: python3 voip_scanner.py --help"
echo ""
