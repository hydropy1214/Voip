# Installation Guide - Enterprise VoIP Security Framework

## System Requirements

### Minimum Requirements
- OS: Linux (Ubuntu 18.04+, Debian 10+, CentOS 7+)
- Bash 4.0 or higher
- Python 3.6+
- 4GB RAM minimum
- 10GB free disk space
- Network connectivity

### Recommended Specifications
- OS: Ubuntu 20.04 LTS or later
- Bash 5.0+
- Python 3.8+
- 8GB+ RAM
- 50GB+ free disk space
- Dedicated VoIP assessment network segment

## Prerequisites Installation

### 1. Ubuntu/Debian Systems

```bash
# Update system packages
sudo apt-get update
sudo apt-get upgrade -y

# Install core dependencies
sudo apt-get install -y \
  curl \
  wget \
  git \
  jq \
  dnsutils \
  iputils-ping \
  netcat-openbsd \
  iptables \
  python3 \
  python3-pip

# Install Python dependencies
pip3 install --upgrade pip
pip3 install pandas requests pexpect
```

### 2. Install Optional Security Tools

#### Masscan (High-speed Port Scanner)
```bash
sudo apt-get install -y git make clang libpcap-dev
git clone https://github.com/robertdavidgraham/masscan
cd masscan
make
sudo make install
masscan --version
```

#### Nuclei (Vulnerability Scanner)
```bash
# Install Go first if not present
sudo apt-get install -y golang-go

# Install Nuclei
go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest

# Add to PATH
export PATH=$PATH:$(go env GOPATH)/bin
nuclei -version

# Download templates
nuclei -update-templates
```

#### Nmap (Network Mapper)
```bash
sudo apt-get install -y nmap
nmap --version
```

#### Fail2ban (Intrusion Prevention)
```bash
sudo apt-get install -y fail2ban
sudo systemctl enable fail2ban
sudo systemctl start fail2ban
```

#### Hydra (Brute-force Tool)
```bash
sudo apt-get install -y hydra
hydra --version
```

### 3. CentOS/RHEL Systems

```bash
# Update system
sudo yum update -y

# Install core dependencies
sudo yum install -y \
  curl \
  wget \
  git \
  jq \
  bind-utils \
  nc \
  iptables \
  python3 \
  python3-devel

# Install development tools for compilation
sudo yum groupinstall -y "Development Tools"

# Python packages
pip3 install --upgrade pip
pip3 install pandas requests pexpect
```

## Framework Installation

### Step 1: Clone Repository

```bash
cd /opt
sudo git clone https://github.com/yourusername/voip-security.git
cd voip-security
sudo chown -R $USER:$USER .
```

### Step 2: Make Scripts Executable

```bash
chmod +x enterprise_voip_security_framework.sh
chmod +x cdr_fraud_analyzer.py
```

### Step 3: Create Configuration Files

```bash
# Create directories
mkdir -p logs results

# Create sample input files
cat > shodan_ips.txt << EOF
192.168.1.10
192.168.1.20
192.168.1.30
EOF

# Create sample CDR file (if testing)
cat > asterisk_cdr.csv << EOF
calldate,src_extension,dst_number,duration_seconds
2024-01-15 10:23:45,101,+12345678901,120
2024-01-15 11:15:30,102,+442071234567,300
2024-01-15 12:45:12,103,+61298765432,45
EOF
```

### Step 4: Configure Framework Variables

```bash
# Edit the script to customize (optional)
vim enterprise_voip_security_framework.sh

# Key variables to customize:
# - MASSCAN_RATE: Port scan speed (default: 5000 pps)
# - THREADS: Parallel jobs (default: 20)
# - NUCLEI_SEVERITY: Severity levels to report (default: critical,high,medium)
```

### Step 5: Verify Installation

```bash
# Test script syntax
bash -n enterprise_voip_security_framework.sh

# Test Python script
python3 -m py_compile cdr_fraud_analyzer.py

# Check dependencies
command -v masscan && echo "✓ Masscan installed" || echo "✗ Masscan not found"
command -v nuclei && echo "✓ Nuclei installed" || echo "✗ Nuclei not found"
command -v nmap && echo "✓ Nmap installed" || echo "✗ Nmap not found"
command -v jq && echo "✓ jq installed" || echo "✗ jq not found"
```

## Running the Framework

### Basic Execution

```bash
# Run full assessment
bash enterprise_voip_security_framework.sh

# Run with debug mode
DEBUG=1 bash enterprise_voip_security_framework.sh
```

### CDR Analysis Only

```bash
python3 cdr_fraud_analyzer.py asterisk_cdr.csv
```

### Custom Nuclei Scanning

```bash
nuclei -l shodan_ips.txt -t nuclei_voip_templates.yaml -o nuclei_results.txt
```

## Troubleshooting Installation

### Issue: Permission Denied

```bash
# Solution
chmod +x enterprise_voip_security_framework.sh
chmod +x cdr_fraud_analyzer.py

# Or run with bash explicitly
bash enterprise_voip_security_framework.sh
```

### Issue: Command Not Found

```bash
# Check PATH
echo $PATH

# Add Go bin to PATH (if using Nuclei)
export PATH=$PATH:$(go env GOPATH)/bin
echo 'export PATH=$PATH:$(go env GOPATH)/bin' >> ~/.bashrc
```

### Issue: Masscan Requires Root

```bash
# Run with sudo
sudo bash enterprise_voip_security_framework.sh

# Or grant capabilities (not recommended for security reasons)
sudo setcap cap_net_raw=ep /usr/bin/masscan
```

### Issue: Python Module Errors

```bash
# Install missing modules
pip3 install pandas
pip3 install requests
pip3 install pexpect

# Verify installation
python3 -c "import pandas; import requests; print('OK')"
```

### Issue: jq Not Installed

```bash
# Ubuntu/Debian
sudo apt-get install -y jq

# CentOS/RHEL
sudo yum install -y jq
```

## Security Hardening

### 1. Restrict File Permissions

```bash
# Make scripts read-only for others
chmod 750 enterprise_voip_security_framework.sh
chmod 750 cdr_fraud_analyzer.py

# Restrict directory access
chmod 700 logs/
chmod 700 results/
```

### 2. Create Dedicated User

```bash
# Create unprivileged user
sudo useradd -r -s /bin/bash voip-scanner
sudo usermod -aG sudo voip-scanner  # If needed for tool execution

# Assign ownership
sudo chown -R voip-scanner:voip-scanner /opt/voip-security
```

### 3. Configure Fail2ban

```bash
# Copy configurations (generated by framework)
sudo cp results/asterisk.conf /etc/fail2ban/filter.d/
sudo cp results/asterisk-sip.conf /etc/fail2ban/jail.d/

# Reload fail2ban
sudo systemctl reload fail2ban
```

## Performance Tuning

### For Large-Scale Scans

```bash
# Edit framework configuration
cat > /tmp/tuning.conf << EOF
MASSCAN_RATE=10000        # Increase scan speed
THREADS=50                # More parallel jobs
TIMEOUT=5                 # Reduce timeout
EOF

# Apply in script or via environment
export MASSCAN_RATE=10000
export THREADS=50
bash enterprise_voip_security_framework.sh
```

### Increase System Limits

```bash
# Temporary
ulimit -n 65535
ulimit -u 4096

# Persistent (/etc/security/limits.conf)
sudo bash << 'EOF'
cat >> /etc/security/limits.conf << 'LIMITS'
*       soft    nofile  65535
*       hard    nofile  65535
*       soft    nproc   4096
*       hard    nproc   4096
LIMITS
EOF
```

## Docker Installation (Alternative)

### Build Docker Image

```dockerfile
FROM ubuntu:20.04

RUN apt-get update && apt-get install -y \
    curl wget git jq dnsutils netcat-openbsd \
    python3 python3-pip masscan nmap

RUN pip3 install pandas requests pexpect

WORKDIR /opt/voip-security
COPY . .

RUN chmod +x *.sh *.py

ENTRYPOINT ["bash", "enterprise_voip_security_framework.sh"]
```

### Build and Run

```bash
# Build
docker build -t voip-security:latest .

# Run
docker run -v $(pwd)/data:/opt/voip-security/data \
           -v $(pwd)/results:/opt/voip-security/results \
           voip-security:latest
```

## Verification Checklist

- [ ] Bash 4.0+ installed
- [ ] Python 3.6+ installed
- [ ] Core tools (jq, curl, awk, grep) available
- [ ] Nuclei templates updated
- [ ] Input files (shodan_ips.txt) prepared
- [ ] Output directories created
- [ ] File permissions set correctly
- [ ] Network connectivity verified
- [ ] System limits increased (for large scans)
- [ ] Security groups/firewall configured for VoIP ports

## Next Steps

1. Review [README.md](README.md) for framework overview
2. Prepare input data (IP addresses, CDR files)
3. Run initial assessment: `bash enterprise_voip_security_framework.sh`
4. Review results in `results/` directory
5. Implement hardening recommendations from reports
6. Schedule regular assessments

---

**Installation Guide Version:** 1.0  
**Last Updated:** 2024
