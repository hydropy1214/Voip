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
  - SIP banner grabbing and version extraction (RFC 3261 §20.35)
  - HTTP service identification
  - SNMP community string probing
  - Fingerprint database generation (valid JSON array)

- **Phase 3: Advanced Vulnerability & CVE Detection**
  - Nuclei integration with VoIP/SIP templates
  - 25+ CVE-specific tests including:
    - CVE-2021-30461 (VoIPmonitor RCE)
    - CVE-2021-26260 (3CX Auth Bypass)
    - CVE-2020-9496 (OFBiz Auth Bypass)
    - CVE-2019-11334 (FreePBX RCE)
    - CVE-2020-12701 (Asterisk Info Disclosure)
  - Exploit scenarios: Anonymous registration, default credentials, header injection, SSRF
  - Brute-force resistance testing via hydra

- **Phase 7: SIP Enumeration & Method Fuzzing** *(v3.0)*
  - Tests all 10 SIP methods (OPTIONS, REGISTER, INVITE, SUBSCRIBE, NOTIFY, PUBLISH, INFO, UPDATE, REFER, MESSAGE)
  - User enumeration via response code differentiation (401 vs 403 vs 404)
  - Server version disclosure detection via Server/User-Agent headers (RFC 3261 §20.35/20.41)
  - Unauthenticated SUBSCRIBE/NOTIFY presence abuse testing (RFC 3265)

- **Phase 8: Extension Scanning & User Enumeration** *(v3.0)*
  - Probes 30+ common extensions (100–9999, operator, admin, guest, etc.)
  - Voicemail access without PIN detection
  - IVR bypass via extension 0
  - Atomic writes with per-process temp files to avoid race conditions
  - Results written to `results/valid_extensions.txt`

- **Phase 9: RTP/RTCP Vulnerability Testing** *(v3.0)*
  - RTCP information disclosure detection (RFC 3550 §6)
  - Wide RTP port exposure scanning
  - SRTP enforcement validation (unencrypted media acceptance, RFC 3711)
  - Media-layer attack surface mapping

- **Phase 10: Credential Harvesting & Auth Bypass** *(v3.0)*
  - SIP Digest bypass tests (empty response field, null nonce) with documented prerequisites
  - Registration hijacking attempts
  - Call interception via unauthenticated REFER (RFC 3515)
  - 23+ default VoIP credential pairs across HTTP/HTTPS/ports 80/443/8080/8443
  - Multiple admin paths tested per vendor (`/admin/`, `/console/`, `/management/`, etc.)
  - Asterisk AMI brute-force with common presets
  - MD5/missing-qop digest weakness detection (RFC 7616)
  - TLS `-k` usage explicitly logged as DEBUG warning

- **Phase 11: Vendor-Specific CVE Testing** *(v3.0)*
  - **Cisco CUCM**: CVE-2021-1397 (SSRF), CVE-2020-3161 (IP Phone RCE)
  - **Avaya Aura**: CVE-2021-22502 (unauthenticated RCE)
  - **Grandstream UCM6xxx**: CVE-2022-37397 (SQL injection)
  - **Polycom**: CVE-2019-9222 (default credentials)
  - **Yealink DM**: CVE-2021-27561 (unauthenticated RCE)
  - **Kamailio/OpenSIPS**: CVE-2019-15752, CVE-2021-25956 (MI/XMLRPC exposure)
  - **FreePBX**: CVE-2022-26272 (module upload RCE)
  - **3CX**: CVE-2021-26260/26261 (unauthenticated API)
  - **Elastix/Issabel**: CVE-2012-4869 (LFI via vtigercrm)

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
# Basic usage (auto-detects targets.txt or falls back to shodan_ips.txt)
bash enterprise_voip_security_framework.sh

# Explicit targets file
bash enterprise_voip_security_framework.sh /path/to/targets.txt

# Override threading and timeout via environment variables
VOIP_THREADS=10 VOIP_TIMEOUT=15 bash enterprise_voip_security_framework.sh targets.txt

# Debug mode
DEBUG=1 bash enterprise_voip_security_framework.sh
```

**Input File Priority:**
1. Explicit CLI argument: `bash script.sh /path/to/targets.txt`
2. Auto-detected `targets.txt` in working directory
3. Legacy fallback: `shodan_ips.txt`

**Input Files:**
- `targets.txt` / `shodan_ips.txt` - One IP per line (optional, for Phase 1-3, 7-11)
- `asterisk_cdr.csv` - CDR data with columns: calldate, src_extension, dst_number, duration_seconds (optional, for Phase 4)

**Output Files:**
- `results/verified_voip_vulnerabilities.txt` - Detailed CVE findings
- `results/service_fingerprints.json` - Service discovery data (valid JSON array)
- `results/cve_findings.json` - Structured CVE results (valid JSON array)
- `results/valid_extensions.txt` - Discovered SIP extensions (Phase 8)
- `results/fraud_analysis.txt` - CDR fraud analysis
- `results/hardening_config.txt` - Security configurations
- `results/executive_summary.txt` - High-level assessment
- `logs/voip_security_*.log` - Detailed execution logs

**Requirements:**
- Bash 4.0+ (4.3+ recommended for `wait -n` efficiency)
- Core utilities: awk, grep, sed, jq, python3, curl, nc
- Optional (for extended features): masscan, nuclei, nmap, dig, hydra, snmpwalk

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

The framework detects and tests for 25+ CVEs:

| CVE ID | Vulnerability | Severity | Affected Software |
|--------|---------------|----------|-------------------|
| CVE-2021-30461 | VoIPmonitor RCE | Critical | VoIPmonitor < v24.61 |
| CVE-2021-26260 | 3CX Auth Bypass | Critical | 3CX PhoneSystem < 18.0.1.1 |
| CVE-2021-26261 | 3CX Unauthenticated API | High | 3CX PhoneSystem < 18.0.1.1 |
| CVE-2020-9496 | OFBiz Auth Bypass | Critical | Apache OFBiz |
| CVE-2019-11334 | FreePBX RCE | Critical | FreePBX < 14.0.3.18 |
| CVE-2022-26272 | FreePBX Module Upload RCE | Critical | FreePBX < 15.0.18.6/16.0.19.5 |
| CVE-2020-12701 | Asterisk Info Disclosure | Medium | Asterisk (all) |
| CVE-2021-21224 | Yealink Default Credentials | High | Yealink Devices |
| CVE-2021-27561 | Yealink DM RCE | Critical | Yealink DM < 3.6.0.20 |
| CVE-2021-1397 | Cisco CUCM SSRF | High | CUCM < 12.5(1)SU4 |
| CVE-2020-3161 | Cisco IP Phone RCE | Critical | 7800/8800 series < 14.1 |
| CVE-2021-22502 | Avaya Aura RCE | Critical | Aura AS 8.0.0.0-8.1.3.3 |
| CVE-2022-37397 | Grandstream SQL Injection | Critical | UCM62xx/63xx < 1.0.20.32 |
| CVE-2020-14871 | Asterisk DTLS-SRTP Disclosure | Medium | Asterisk |
| CVE-2021-25956 | OpenSIPS SQL Injection | High | OpenSIPS |
| CVE-2019-15752 | Kamailio Heap Overflow | Critical | Kamailio |
| CVE-2019-9222 | Polycom Default Credentials | High | Polycom PABX |
| CVE-2012-4869 | Elastix LFI | Critical | Elastix 2.x |
| Log4Shell | Log4j RCE | Critical | Systems using Log4j |

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
# Create IP list (targets.txt takes priority over shodan_ips.txt)
echo "192.168.1.10" > targets.txt
echo "10.0.0.20" >> targets.txt

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
# Default (auto-detects targets.txt or shodan_ips.txt)
bash enterprise_voip_security_framework.sh

# With custom targets file and tuned parameters
VOIP_THREADS=10 VOIP_TIMEOUT=15 bash enterprise_voip_security_framework.sh /path/to/ips.txt
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

### grep -P Not Supported
On systems without PCRE (Alpine, BSD), the script automatically detects this at startup and uses compatible regex alternatives. A `[WARN]` log entry will indicate the fallback is active.

---

## Performance Considerations

- **Threading**: Default 20 parallel jobs - override with `VOIP_THREADS=N`
- **Timeout**: Default 10 seconds per probe - override with `VOIP_TIMEOUT=N`
- **Masscan Rate**: Default 5000 pps - adjust `MASSCAN_RATE` variable in script
- **Job control**: Uses `wait -n` (bash 4.3+) to minimize CPU spin; falls back to 100ms sleep on older bash

For large scans (1000+ IPs):
```bash
VOIP_THREADS=50 VOIP_TIMEOUT=5 bash enterprise_voip_security_framework.sh targets.txt
```

---

## Compliance & Standards

This framework supports compliance with:
- **NIST Cybersecurity Framework** - VoIP security assessment
- **PCI DSS** - VoIP fraud detection
- **HIPAA** - Secure voice communications
- **SOC 2** - Security monitoring and logging
- **ISO 27001** - Information security controls
- **RFC 3261** - SIP protocol compliance (all SIP packets use compliant headers)

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

### v3.0.0 (Current)
- Added Phase 7: SIP Enumeration & Method Fuzzing (all 10 RFC 3261 methods)
- Added Phase 8: Extension Scanning & User Enumeration with atomic file writes
- Added Phase 9: RTP/RTCP Vulnerability Testing
- Added Phase 10: Credential Harvesting & Auth Bypass (23+ credential pairs, HTTPS, AMI)
- Added Phase 11: Vendor-Specific CVE Testing (9 vendors, 19 CVEs)
- Multi-target input: targets.txt priority > shodan_ips.txt fallback
- Environment variable configuration: `VOIP_THREADS`, `VOIP_TIMEOUT`
- Fixed: all `timeout N (...)` subshell syntax errors → `timeout N bash -c "..."`
- Fixed: `[[ ! command -v hydra ]]` → `! command -v hydra`
- Fixed: `echo "═" * 70` glob expansion → `printf '═%.0s' {1..70}`
- Fixed: `append_cve_finding` now produces valid JSON array with flock-based concurrency safety
- Fixed: `append_fingerprint` now produces valid JSON array
- Replaced busy-wait loops with `wait -n` (bash 4.3+) / 100ms sleep fallback
- Added cleanup trap for SIGTERM/SIGINT
- Added PCRE grep portability check at startup
- Replaced `grep -oP` with POSIX-compatible alternatives
- Expanded CVE database to 25+ entries
- RFC 3261 compliance comments on all SIP packet construction
- Explicit logging for `-k` (insecure TLS) usage in credential testing

### v2.0.0
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

**Last Updated:** 2026
**Author:** VoIP Security Team
**Status:** Production Ready
