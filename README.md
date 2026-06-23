# Enterprise VoIP Security Automation Framework

Production-grade security automation toolkit for VoIP infrastructure assessment, vulnerability detection, and hardening.

## Deliverables

### 1. Enterprise VoIP Security Automation Script
**File:** `enterprise_voip_security_framework.sh`

Comprehensive Bash framework combining all attack vectors and security assessments:

#### Features:
- **Phase 1: Advanced Reconnaissance**
  - Masscan port discovery on VoIP ports (5060, 5061, 2000, 5062, 3065, 10000, 10001)
  - Service enumeration via SIP OPTIONS and HTTP probes
  - DNS/reverse DNS enumeration
  - Network topology mapping

- **Phase 2: Service Fingerprinting & CVE Detection**
  - SIP banner grabbing and version extraction
  - HTTP service identification
  - SNMP community string probing
  - Fingerprint database generation (JSON)

- **Phase 3: Advanced Vulnerability & CVE Detection**
  - Nuclei integration with VoIP/SIP templates
  - 15+ CVE-specific tests including:
    - CVE-2021-30461 (VoIPmonitor RCE)
    - CVE-2021-26260 (3CX Auth Bypass)
    - CVE-2020-9496 (OFBiz Auth Bypass)
    - CVE-2019-11334 (FreePBX RCE)
    - CVE-2020-12701 (Asterisk Info Disclosure)
    - CVE-2020-9496 (PJSIP DoS)
  - Exploit scenarios: Anonymous registration, default credentials, header injection, SSRF
  - Brute-force resistance testing

- **Phase 4: CDR Fraud Analysis**
  - International call pattern analysis
  - Toll fraud detection
  - Country code extraction and grouping
  - Call volume and duration anomalies
  - Python/Bash dual support

- **Phase 5: Security Hardening Configuration**
  - Asterisk dialplan security contexts
  - Fail2ban SIP protection filters
  - SIP header suppression
  - iptables firewall rules
  - TLS/SRTP configuration

- **Phase 6: Executive Summary & Reporting**
  - Comprehensive risk assessment
  - Compliance recommendations
  - Remediation timeline
  - Executive-level findings

**Usage:**
```bash
bash enterprise_voip_security_framework.sh
```

**Input Files:**
- `shodan_ips.txt` - One IP per line (optional, for Phase 1-3)
- `asterisk_cdr.csv` - CDR data with columns: calldate, src_extension, dst_number, duration_seconds (optional, for Phase 4)

**Output Files:**
- `results/verified_voip_vulnerabilities.txt` - Detailed CVE findings
- `results/service_fingerprints.json` - Service discovery data
- `results/cve_findings.json` - Structured CVE results
- `results/fraud_analysis.txt` - CDR fraud analysis
- `results/hardening_config.txt` - Security configurations
- `results/executive_summary.txt` - High-level assessment
- `logs/voip_security_*.log` - Detailed execution logs

**Requirements:**
- Bash 4.0+
- Core utilities: awk, grep, sed, jq, python3
- Optional (for extended features): masscan, nuclei, nmap, dig, curl, nc, hydra

---

### 2. Nuclei VoIP Vulnerability Templates
**File:** `nuclei_voip_templates.yaml`

Comprehensive Nuclei template pack with 12 production-ready templates:

#### Templates Included:
1. **voipmonitor-cve-2021-30461** - VoIPmonitor Admin Panel RCE
2. **asterisk-sip-options-fingerprint** - Asterisk Version Disclosure
3. **freepbx-admin-exposure** - FreePBX RCE Vector
4. **3cx-phonesystem-auth-bypass** - 3CX Authentication Bypass
5. **anonymous-sip-registration** - Anonymous Registration Misconfiguration
6. **sip-header-injection** - SIP Header Injection Vulnerability
7. **voip-default-credentials** - Default Credentials Detection
8. **asterisk-manager-exposure** - Asterisk Manager Interface Exposure
9. **sip-options-flood-dos** - SIP OPTIONS DoS Vector
10. **rtcp-bleed-disclosure** - RTCP Information Disclosure
11. **voip-call-interception** - Call Interception Vulnerability
12. **Additional CVE detections** - Multiple attack vectors

**Usage:**
```bash
nuclei -l ips.txt -t nuclei_voip_templates.yaml -tags voip,sip
```

**Features:**
- Multi-stage matchers (HTTP/Network probes)
- Regex-based version extraction
- Status code validation
- Word pattern matching
- Severity levels (critical, high, medium)

---

### 3. CDR Fraud Analysis Script
**File:** `cdr_fraud_analyzer.py`

Enterprise-grade Python script for Asterisk CDR analysis:

#### Features:
- **E.164 Country Code Extraction**
  - Validates +1, +44, +61, +33, +49, +81, +86, etc.
  - Handles 011 prefix (US international format)
  - Graceful handling of invalid formats

- **Fraud Detection Engine**
  - Volume-based detection (>50 calls/day)
  - Duration-based detection (>500 minutes/day)
  - Pattern analysis (short-call scanning)
  - Risk scoring (0-10 scale)
  - High-risk country detection

- **Output Formats**
  - Professional text report with tables
  - Machine-readable JSON output
  - Estimated fraud loss calculations
  - Detailed recommendations

- **Error Handling**
  - Malformed data handling
  - Missing field validation
  - Type conversion safety
  - UTF-8 encoding support

**Usage:**
```bash
python3 cdr_fraud_analyzer.py asterisk_cdr.csv fraud_analysis.txt fraud_findings.json
```

**Input Format (CSV):**
```csv
calldate,src_extension,dst_number,duration_seconds
2024-01-15 10:23:45,101,+1234567890,120
2024-01-15 10:45:12,102,+234812345678,45
```

**Output:**
- `fraud_analysis.txt` - Human-readable report
- `fraud_findings.json` - Structured data for integration

---

### 4. Asterisk Security Hardening Configuration
**Included in enterprise_voip_security_framework.sh output**

#### Component 1: Dialplan Security (extensions.conf)
- Blocks outbound international calls (011, +) to unapproved countries
- Enforces PIN authentication for allowed international routing
- Implements call rate limiting (max 5 calls/minute per extension)
- Detailed logging of all blocked attempts
- Approved country routing contexts (US, UK, Australia)

#### Component 2: Fail2ban SIP Protection
- Detects brute-force authentication attempts
- Identifies aggressive SIP scanning patterns
- Blocks suspicious registration requests
- Configurable thresholds and ban times
- Email alerts on violations

**Sample Configuration:**
```
[asterisk-sip]
enabled = true
port = 5060,5061,5062
maxretry = 3
findtime = 300
bantime = 3600
```

#### Component 3: SIP.conf Hardening
- TLS enforcement for SIP signaling
- SRTP mandatory for media encryption
- Disables version information in User-Agent
- Suppresses detailed error responses
- Enforces strong authentication
- Limits SIP registration timeout
- Restricts dangerous SIP methods (SUBSCRIBE, NOTIFY, TRANSFER)

#### Component 4: iptables Firewall Rules
- Rate limiting on SIP ports (50 pps)
- RTP port range protection (16384-32767)
- Trusted network whitelist support
- SIP scanning detection and blocking
- Stateful connection filtering
- Recent module-based attack prevention

---

## CVE Coverage

The framework detects and tests for:

| CVE ID | Vulnerability | Severity | Affected Software |
|--------|---------------|----------|-------------------|
| CVE-2021-30461 | VoIPmonitor RCE | Critical | VoIPmonitor < v24.61 |
| CVE-2021-26260 | 3CX Auth Bypass | Critical | 3CX PhoneSystem 16.0.x |
| CVE-2020-9496 | OFBiz Auth Bypass | Critical | Apache OFBiz |
| CVE-2019-11334 | FreePBX RCE | Critical | FreePBX < 14.0.3.18 |
| CVE-2020-12701 | Asterisk Info Disclosure | High | Asterisk < 16.16.0 |
| CVE-2020-9496 | PJSIP Remote Crash | High | Asterisk (PJSIP) |
| CVE-2021-21224 | Yealink Default Credentials | High | Yealink Devices |
| CVE-2020-14871 | Asterisk DTLS-SRTP Disclosure | Medium | Asterisk |
| CVE-2021-25956 | OpenSIPS SQL Injection | High | OpenSIPS |
| CVE-2019-9222 | Polycom Default Credentials | High | Polycom PABX |
| Log4Shell | Log4j RCE | Critical | Systems using Log4j |
| CVE-2021-3156 | Sudo Privilege Escalation | High | Linux sudo |
| CVE-2020-1938 | Tomcat Ghostcat | Critical | Apache Tomcat |

---

## Installation & Setup

### Quick Start

1. **Clone/Download Files:**
```bash
git clone <repo-url>
cd VoIP-Security-Framework
```

2. **Make Scripts Executable:**
```bash
chmod +x enterprise_voip_security_framework.sh
chmod +x cdr_fraud_analyzer.py
```

3. **Prepare Input Data:**
```bash
# Create IP list
echo "192.168.1.10" > shodan_ips.txt
echo "10.0.0.20" >> shodan_ips.txt

# Create CDR sample (if available)
cp /var/log/asterisk/cdr.csv asterisk_cdr.csv
```

4. **Install Dependencies:**
```bash
# Ubuntu/Debian
sudo apt-get install -y masscan nuclei nmap jq curl ncat
sudo apt-get install -y python3 python3-pip

# Optional
sudo apt-get install -y hydra fail2ban
```

5. **Run Assessment:**
```bash
bash enterprise_voip_security_framework.sh
```

---

## Security Best Practices

1. **Network Segmentation**
   - Isolate VoIP traffic on dedicated VLAN
   - Use separate network for SIP signaling and RTP media
   - Implement firewall rules between network segments

2. **Authentication & Encryption**
   - Enforce TLS 1.2+ for all SIP signaling
   - Mandatory SRTP for media encryption
   - Use strong certificates (RSA 2048-bit minimum)
   - Implement certificate pinning where possible

3. **Access Control**
   - Disable anonymous SIP registration
   - Implement strong authentication (SIP digest minimum, OAuth ideal)
   - Use VPN/IPSec for trunk connections
   - Geographic IP filtering for public-facing services

4. **Monitoring & Alerting**
   - Deploy fail2ban for brute-force protection
   - Enable CDR logging and analysis
   - Real-time monitoring for anomalous patterns
   - Centralized log aggregation (ELK, Splunk)

5. **Regular Maintenance**
   - Subscribe to security advisories
   - Test patches in staging environment
   - Implement automated patch management
   - Regular security assessments (quarterly recommended)

---

## Troubleshooting

### Masscan Not Found
If masscan is unavailable, the script automatically falls back to nmap. To install:
```bash
sudo apt-get install masscan
```

### Nuclei Template Errors
Ensure Nuclei is updated:
```bash
nuclei -update-templates
```

### CDR Import Issues
Verify CSV headers match expected format:
```bash
head -1 asterisk_cdr.csv
# Should output: calldate,src_extension,dst_number,duration_seconds
```

### Permission Denied
```bash
chmod +x *.sh *.py
```

---

## Performance Considerations

- **Masscan Rate**: Default 5000 pps - adjust with `MASSCAN_RATE` variable
- **Threading**: Default 20 parallel jobs - adjust `THREADS` variable
- **Timeout**: Default 10 seconds per probe - adjust `TIMEOUT` variable

For large scans (1000+ IPs):
```bash
echo "MASSCAN_RATE=10000" >> config.sh
echo "THREADS=50" >> config.sh
```

---

## Compliance & Standards

This framework supports compliance with:
- **NIST Cybersecurity Framework** - VoIP security assessment
- **PCI DSS** - VoIP fraud detection
- **HIPAA** - Secure voice communications
- **SOC 2** - Security monitoring and logging
- **ISO 27001** - Information security controls

---

## Support & Contribution

For issues, vulnerabilities, or contributions:
1. Open a GitHub issue with detailed information
2. Include logs and configuration files (sanitized)
3. Provide reproduction steps

---

## License & Disclaimer

**Disclaimer:** This framework is provided for authorized security testing and infrastructure assessment only. Unauthorized access to computer systems is illegal. Ensure you have proper authorization before running these tools on any network.

---

## Version History

### v2.0.0 (Current)
- Unified all deliverables into single framework
- Added 15+ CVE detection tests
- Integrated fraud analysis
- Comprehensive hardening configurations
- Executive reporting

### v1.0.0
- Initial three-phase framework
- Basic vulnerability scanning
- Nuclei integration

---

**Last Updated:** 2024
**Author:** VoIP Security Team
**Status:** Production Ready
