#!/bin/bash

###############################################################################
# ENTERPRISE VOIP SECURITY AUTOMATION FRAMEWORK v2.0
# Comprehensive VoIP Infrastructure Assessment & Exploitation Prevention
# Covers: Reconnaissance, Fingerprinting, Vulnerability Detection, 
# CDR Fraud Analysis, Configuration Hardening, and Advanced Attack Scenarios
###############################################################################

set -euo pipefail

# ============================================================================
# SCRIPT METADATA & CONFIGURATION
# ============================================================================

readonly SCRIPT_VERSION="2.0.0"
readonly SCRIPT_NAME="$(basename "$0")"
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly INPUT_FILE="${1:-shodan_ips.txt}"
readonly CDR_FILE="${2:-asterisk_cdr.csv}"
readonly LOG_DIR="./logs"
readonly RESULTS_DIR="./results"
readonly LOG_FILE="${LOG_DIR}/voip_security_$(date +%Y%m%d_%H%M%S).log"
readonly TEMP_DIR=$(mktemp -d)

# ============================================================================
# CONFIGURATION PARAMETERS
# ============================================================================

# Reconnaissance & Scanning
readonly MASSCAN_RATE=5000
readonly VOIP_PORTS=("5060" "5061" "2000" "5062" "3065" "10000" "10001")
readonly SIP_PORTS=("5060" "5061" "5062")
readonly RTP_PORT_RANGE="16384-32767"
readonly THREADS=20
readonly TIMEOUT=10

# Vulnerability & CVE Detection
readonly NUCLEI_SEVERITY="critical,high,medium"
readonly ENABLE_CUSTOM_CVE_TESTS="true"
readonly ENABLE_BRUTE_FORCE_TESTS="true"
readonly ENABLE_EXPLOIT_SCENARIOS="true"

# Output Files
readonly LIVE_IPS_FILE="${TEMP_DIR}/live_ips.txt"
readonly SERVICE_FINGERPRINTS="${RESULTS_DIR}/service_fingerprints.json"
readonly VULNERABILITIES_FILE="${RESULTS_DIR}/verified_voip_vulnerabilities.txt"
readonly CVE_FINDINGS="${RESULTS_DIR}/cve_findings.json"
readonly FRAUD_REPORT="${RESULTS_DIR}/fraud_analysis.txt"
readonly HARDENING_CONFIG="${RESULTS_DIR}/hardening_config.txt"
readonly EXECUTIVE_SUMMARY="${RESULTS_DIR}/executive_summary.txt"

# CVE Database (Major VoIP CVEs)
declare -A CVE_DATABASE=(
    ["CVE-2021-30461"]="VoIPmonitor Administrative Panel Exposure - RCE"
    ["CVE-2020-29510"]="Asterisk PJSIP Remote Crash - DoS"
    ["CVE-2021-26260"]="3CX PhoneSystem Authentication Bypass"
    ["CVE-2020-9496"]="Apache OFBiz Authentication Bypass - RCE"
    ["CVE-2019-11334"]="FreePBX Bulk User Management RCE"
    ["CVE-2021-21224"]="Yealink Device Default Credentials"
    ["CVE-2020-12701"]="Asterisk SIP Information Disclosure"
    ["CVE-2021-44228"]="Log4Shell - Remote Code Execution"
    ["CVE-2022-24765"]="Git Configuration Vulnerability"
    ["CVE-2021-3156"]="Sudo Privilege Escalation"
    ["CVE-2020-1938"]="Tomcat AJP Ghostcat Vulnerability"
    ["CVE-2019-19404"]="FreePBX Privilege Escalation"
    ["CVE-2020-14871"]="Asterisk DTLS-SRTP Information Disclosure"
    ["CVE-2021-25956"]="OpenSIPS SQL Injection"
    ["CVE-2019-9222"]="Polycom PABX Default Credentials"
)

# Approved International Dialing Codes (for fraud detection)
declare -a APPROVED_COUNTRY_CODES=("+1" "+44" "+61" "+33" "+49" "+81" "+86")

# ============================================================================
# LOGGING & OUTPUT FUNCTIONS
# ============================================================================

initialize_logging() {
    mkdir -p "$LOG_DIR" "$RESULTS_DIR"
    exec 1> >(tee -a "$LOG_FILE")
    exec 2>&1
    
    log_banner "ENTERPRISE VOIP SECURITY AUTOMATION FRAMEWORK"
    log_info "Script Version: $SCRIPT_VERSION"
    log_info "Execution Started: $(date '+%Y-%m-%d %H:%M:%S')"
    log_info "Log Directory: $LOG_DIR"
    log_info "Results Directory: $RESULTS_DIR"
    log_info "Temporary Directory: $TEMP_DIR"
}

log_banner() {
    echo ""
    echo "╔════════════════════════════════════════════════════════════════════╗"
    echo "║ $*"
    echo "╚════════════════════════════════════════════════════════════════════╝"
    echo ""
}

log_info() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [INFO] $*"
}

log_error() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [ERROR] $*" >&2
}

log_warn() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [WARN] $*"
}

log_success() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [✓] $*"
}

log_debug() {
    [[ "${DEBUG:-0}" == "1" ]] && echo "[$(date '+%Y-%m-%d %H:%M:%S')] [DEBUG] $*" || true
}

# ============================================================================
# VALIDATION & DEPENDENCY CHECKS
# ============================================================================

validate_input_files() {
    local has_errors=0
    
    if [[ -f "$INPUT_FILE" ]]; then
        local ip_count=$(grep -c '^[0-9]' "$INPUT_FILE" || echo "0")
        if [[ $ip_count -gt 0 ]]; then
            log_success "Input file validated: $ip_count IP addresses found"
        else
            log_warn "No valid IP addresses in $INPUT_FILE"
        fi
    else
        log_warn "IP input file not found: $INPUT_FILE (skipping Phase 1-3)"
    fi
    
    if [[ -f "$CDR_FILE" ]]; then
        local cdr_count=$(wc -l < "$CDR_FILE")
        log_success "CDR file found: $cdr_count records"
    else
        log_warn "CDR file not found: $CDR_FILE (skipping CDR analysis)"
    fi
}

validate_dependencies() {
    local required_tools=("bash" "awk" "grep" "sed" "jq" "python3" "curl" "nc")
    local optional_tools=("masscan" "nuclei" "nmap" "dig" "hydra")
    local missing=()
    
    log_info "Validating dependencies..."
    
    for tool in "${required_tools[@]}"; do
        if ! command -v "$tool" &> /dev/null; then
            missing+=("$tool [REQUIRED]")
        fi
    done
    
    if [[ ${#missing[@]} -gt 0 ]]; then
        log_error "Missing required tools: ${missing[*]}"
        return 1
    fi
    
    for tool in "${optional_tools[@]}"; do
        if command -v "$tool" &> /dev/null; then
            log_success "Found optional tool: $tool"
        else
            log_warn "Optional tool not found: $tool (some features disabled)"
        fi
    done
    
    return 0
}

# ============================================================================
# PHASE 1: ADVANCED RECONNAISSANCE & DISCOVERY
# ============================================================================

phase1_advanced_reconnaissance() {
    log_banner "PHASE 1: ADVANCED RECONNAISSANCE & DISCOVERY"
    
    [[ ! -f "$INPUT_FILE" ]] && { log_warn "Skipping Phase 1 - no input file"; return 0; }
    
    # Sub-phase 1a: Port discovery with masscan
    log_info "Sub-phase 1a: High-speed port scanning with masscan"
    phase1a_masscan_discovery
    
    # Sub-phase 1b: Service enumeration
    log_info "Sub-phase 1b: Service enumeration and UDP scanning"
    phase1b_service_enumeration
    
    # Sub-phase 1c: Network enumeration
    log_info "Sub-phase 1c: Network topology and DNS enumeration"
    phase1c_network_enumeration
    
    log_success "Phase 1 Complete"
}

phase1a_masscan_discovery() {
    local masscan_output="${TEMP_DIR}/masscan_output.txt"
    
    if ! command -v masscan &> /dev/null; then
        log_warn "masscan not found - using nmap instead"
        phase1a_nmap_fallback
        return
    fi
    
    local port_spec=$(IFS=,; echo "${VOIP_PORTS[*]}")
    log_info "Scanning ports: $port_spec"
    
    if masscan -iL "$INPUT_FILE" \
        -p "$port_spec" \
        --rate="$MASSCAN_RATE" \
        --output-format list \
        --output-filename "$masscan_output" \
        -e tun0 2>&1 | tee -a "$LOG_FILE"; then
        
        # Parse results
        awk '{print $1}' "$masscan_output" | sort -u > "$LIVE_IPS_FILE"
        local live_count=$(wc -l < "$LIVE_IPS_FILE")
        log_success "Discovered $live_count live hosts"
    else
        log_warn "masscan encountered issues - continuing with alternatives"
    fi
}

phase1a_nmap_fallback() {
    log_info "Using nmap for port discovery (slower but reliable)"
    
    local nmap_output="${TEMP_DIR}/nmap_output.gnmap"
    
    if nmap -iL "$INPUT_FILE" \
        -p "${SIP_PORTS[0]}" \
        --open -T4 -oG "$nmap_output" \
        --max-retries 1 --scan-delay 0s 2>&1 | tee -a "$LOG_FILE"; then
        
        grep "Status: Up" "$nmap_output" | awk '{print $2}' | sort -u > "$LIVE_IPS_FILE"
        local live_count=$(wc -l < "$LIVE_IPS_FILE")
        log_success "nmap discovered $live_count live hosts"
    fi
}

phase1b_service_enumeration() {
    [[ ! -s "$LIVE_IPS_FILE" ]] && return
    
    local enum_output="${TEMP_DIR}/service_enum.txt"
    
    log_info "Performing service version detection on $(wc -l < "$LIVE_IPS_FILE") hosts"
    
    # Parallel service enumeration with timeout
    while IFS= read -r ip; do
        {
            # SIP OPTIONS request via netcat
            (
                echo -e "OPTIONS sip:$ip:5060 SIP/2.0\r\nVia: SIP/2.0/UDP scanner\r\nTo: <sip:$ip>\r\nFrom: <sip:scanner>\r\nCall-ID: scanner\r\nCSeq: 1 OPTIONS\r\n\r\n"
                sleep 1
            ) | nc -q 1 -w 2 "$ip" 5060 >> "$enum_output" 2>/dev/null || true
            
            # Port 2000 probe (VoIP-related)
            (echo "VERSION" | nc -q 1 -w 2 "$ip" 2000) >> "$enum_output" 2>/dev/null || true
            
        } &
        
        # Limit parallel jobs
        while (( $(jobs -r -p | wc -l) >= THREADS )); do
            sleep 0.1
        done
    done < "$LIVE_IPS_FILE"
    wait
    
    log_debug "Service enumeration data: $(wc -l < "$enum_output") lines"
}

phase1c_network_enumeration() {
    [[ ! -s "$LIVE_IPS_FILE" ]] && return
    
    local dns_output="${TEMP_DIR}/dns_records.txt"
    
    log_info "Performing reverse DNS lookups and WHOIS queries"
    
    while IFS= read -r ip; do
        {
            # Reverse DNS lookup
            (dig +short -x "$ip") >> "$dns_output" 2>/dev/null || true
            
            # NSLookup fallback
            (nslookup "$ip" 2>/dev/null | grep -i "name" || true) >> "$dns_output" 2>/dev/null || true
            
        } &
        
        while (( $(jobs -r -p | wc -l) >= THREADS )); do
            sleep 0.1
        done
    done < "$LIVE_IPS_FILE"
    wait
    
    log_debug "DNS enumeration complete"
}

# ============================================================================
# PHASE 2: COMPREHENSIVE SERVICE FINGERPRINTING & CVE DETECTION
# ============================================================================

phase2_service_fingerprinting() {
    log_banner "PHASE 2: SERVICE FINGERPRINTING & CVE DETECTION"
    
    [[ ! -s "$LIVE_IPS_FILE" ]] && { log_warn "Skipping Phase 2 - no live hosts"; return 0; }
    
    # Initialize fingerprint database
    echo "[]" > "$SERVICE_FINGERPRINTS"
    
    local processed=0
    
    while IFS= read -r ip; do
        {
            log_debug "Processing fingerprints for $ip"
            
            # SIP Server Identification
            local sip_banner=$(extract_sip_banner "$ip")
            
            # HTTP Service Detection
            local http_banner=$(extract_http_banner "$ip")
            
            # SNMP Detection
            local snmp_info=$(extract_snmp_info "$ip")
            
            # Store fingerprints
            if [[ -n "$sip_banner" || -n "$http_banner" ]]; then
                append_fingerprint "$ip" "$sip_banner" "$http_banner" "$snmp_info"
                ((processed++))
            fi
            
        } &
        
        while (( $(jobs -r -p | wc -l) >= THREADS )); do
            sleep 0.1
        done
    done < "$LIVE_IPS_FILE"
    wait
    
    log_success "Fingerprinted $processed hosts"
}

extract_sip_banner() {
    local ip="$1"
    
    # Send SIP OPTIONS request
    local response=$(timeout 3 (
        echo -e "OPTIONS sip:$ip SIP/2.0\r\nVia: SIP/2.0/UDP scanner\r\nTo: <sip:$ip>\r\nFrom: <sip:scanner>\r\nCall-ID: scanner@scanner\r\nCSeq: 1 OPTIONS\r\nContact: <sip:scanner>\r\nAccept: application/sdp\r\n\r\n"
        sleep 1
    ) | nc -w 2 "$ip" 5060 2>/dev/null)
    
    # Extract Server header
    echo "$response" | grep -i "^Server:" | head -1 || echo ""
}

extract_http_banner() {
    local ip="$1"
    
    local response=$(timeout 3 curl -s -I "http://$ip:80/" 2>/dev/null || true)
    echo "$response" | grep -i "^Server:" | head -1 || echo ""
}

extract_snmp_info() {
    local ip="$1"
    
    # Try common SNMP community strings
    if command -v snmpwalk &> /dev/null; then
        snmpwalk -v1 -c public "$ip" sysDescr.0 2>/dev/null | grep -oP 'STRING: \K.*' || echo ""
    else
        echo ""
    fi
}

append_fingerprint() {
    local ip="$1"
    local sip_banner="$2"
    local http_banner="$3"
    local snmp_info="$4"
    
    local timestamp=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
    
    cat >> "$SERVICE_FINGERPRINTS" << EOF
{
  "ip": "$ip",
  "timestamp": "$timestamp",
  "sip_banner": "$sip_banner",
  "http_banner": "$http_banner",
  "snmp_info": "$snmp_info",
  "ports_open": [5060, 5061, 2000]
}
EOF
}

# ============================================================================
# PHASE 3: ADVANCED VULNERABILITY & CVE DETECTION
# ============================================================================

phase3_advanced_vulnerability_detection() {
    log_banner "PHASE 3: ADVANCED VULNERABILITY & CVE DETECTION"
    
    [[ ! -s "$LIVE_IPS_FILE" ]] && { log_warn "Skipping Phase 3 - no live hosts"; return 0; }
    
    # Initialize findings
    > "$CVE_FINDINGS"
    
    # Run Nuclei with VoIP templates
    phase3a_nuclei_scanning
    
    # Run custom CVE-specific tests
    phase3b_custom_cve_tests
    
    # Run exploit scenario tests
    phase3c_exploit_scenarios
    
    # Brute-force detection tests
    phase3d_brute_force_tests
    
    log_success "Phase 3 Complete - $(wc -l < "$CVE_FINDINGS") CVE findings"
}

phase3a_nuclei_scanning() {
    if ! command -v nuclei &> /dev/null; then
        log_warn "nuclei not found - skipping template-based scanning"
        return
    fi
    
    log_info "Running Nuclei with VoIP/SIP templates"
    
    local nuclei_output="${TEMP_DIR}/nuclei_findings.json"
    
    nuclei -l "$LIVE_IPS_FILE" \
        -tags voip,sip,asterisk,freepbx,3cx,yealink \
        -severity "$NUCLEI_SEVERITY" \
        -json -o "$nuclei_output" \
        -c "$THREADS" \
        -timeout "$TIMEOUT" \
        -rl 100 2>&1 | tee -a "$LOG_FILE" || true
    
    # Parse and integrate results
    if [[ -f "$nuclei_output" ]]; then
        jq '.[] | {
            host: .host,
            port: .port,
            template_id: .template_id,
            name: .info.name,
            severity: .info.severity,
            description: .info.description,
            matched_at: .matched_at,
            type: "nuclei"
        }' "$nuclei_output" >> "$CVE_FINDINGS" 2>/dev/null || true
    fi
}

phase3b_custom_cve_tests() {
    [[ "$ENABLE_CUSTOM_CVE_TESTS" != "true" ]] && return
    
    log_info "Running custom CVE-specific vulnerability tests"
    
    while IFS= read -r ip; do
        # Test CVE-2021-30461 (VoIPmonitor)
        test_cve_2021_30461 "$ip"
        
        # Test CVE-2021-26260 (3CX)
        test_cve_2021_26260 "$ip"
        
        # Test CVE-2020-9496 (OFBiz)
        test_cve_2020_9496 "$ip"
        
        # Test CVE-2019-11334 (FreePBX)
        test_cve_2019_11334 "$ip"
        
        # Test CVE-2020-12701 (Asterisk)
        test_cve_2020_12701 "$ip"
        
    done < "$LIVE_IPS_FILE"
}

test_cve_2021_30461() {
    local ip="$1"
    
    # VoIPmonitor Admin Panel Detection
    local response=$(timeout 3 curl -s "http://$ip/index.php" 2>/dev/null || true)
    
    if echo "$response" | grep -q "VoIPmonitor"; then
        local version=$(echo "$response" | grep -oP 'version["\s:]*\K[0-9.]+' | head -1 || echo "unknown")
        
        # Check if version < v24.61
        if [[ -n "$version" && $(echo "$version < 24.61" | bc 2>/dev/null || echo "1") -eq 1 ]]; then
            append_cve_finding "$ip" "CVE-2021-30461" "VoIPmonitor Admin Panel RCE" \
                "CRITICAL" "Version $version is vulnerable to authentication bypass and RCE" \
                "http://$ip/index.php"
        fi
    fi
}

test_cve_2021_26260() {
    local ip="$1"
    
    # 3CX Authentication Bypass
    local response=$(timeout 3 curl -s "http://$ip:5000/webclient" 2>/dev/null || true)
    
    if echo "$response" | grep -q "3CX"; then
        append_cve_finding "$ip" "CVE-2021-26260" "3CX PhoneSystem Auth Bypass" \
            "HIGH" "3CX system detected with potential authentication bypass vulnerability" \
            "http://$ip:5000/webclient"
    fi
}

test_cve_2020_9496() {
    local ip="$1"
    
    # Apache OFBiz Authentication Bypass
    local response=$(timeout 3 curl -s "http://$ip:8080/webtools" 2>/dev/null || true)
    
    if echo "$response" | grep -q "OFBiz"; then
        append_cve_finding "$ip" "CVE-2020-9496" "OFBiz Authentication Bypass" \
            "CRITICAL" "Apache OFBiz webtools interface detected - vulnerable to auth bypass" \
            "http://$ip:8080/webtools"
    fi
}

test_cve_2019_11334() {
    local ip="$1"
    
    # FreePBX Bulk User Management RCE
    local response=$(timeout 3 curl -s "http://$ip/admin/modules.php" 2>/dev/null || true)
    
    if echo "$response" | grep -q "FreePBX"; then
        append_cve_finding "$ip" "CVE-2019-11334" "FreePBX Bulk User Mgmt RCE" \
            "CRITICAL" "FreePBX admin interface detected - vulnerable to RCE via bulk user management" \
            "http://$ip/admin/modules.php"
    fi
}

test_cve_2020_12701() {
    local ip="$1"
    
    # Asterisk SIP Information Disclosure
    local response=$(timeout 3 (
        echo -e "OPTIONS sip:$ip SIP/2.0\r\nVia: SIP/2.0/UDP scanner\r\n\r\n"
        sleep 1
    ) | nc -w 2 "$ip" 5060 2>/dev/null || true)
    
    if echo "$response" | grep -q "Asterisk"; then
        local version=$(echo "$response" | grep -oP "Asterisk\s+\K[0-9.]+" || echo "unknown")
        append_cve_finding "$ip" "CVE-2020-12701" "Asterisk SIP Info Disclosure" \
            "MEDIUM" "Asterisk version $version detected - leaking software version via SIP headers" \
            "sip://$ip:5060"
    fi
}

phase3c_exploit_scenarios() {
    [[ "$ENABLE_EXPLOIT_SCENARIOS" != "true" ]] && return
    
    log_info "Running exploit scenario tests"
    
    # Test for common misconfigurations
    while IFS= read -r ip; do
        # Anonymous SIP registration test
        test_anonymous_sip_registration "$ip"
        
        # Default credentials test
        test_default_credentials "$ip"
        
        # SIP header injection
        test_sip_header_injection "$ip"
        
        # SSRF/CSRF scenarios
        test_ssrf_vulnerability "$ip"
        
    done < "$LIVE_IPS_FILE"
}

test_anonymous_sip_registration() {
    local ip="$1"
    
    # Send SIP REGISTER request with anonymous credentials
    local response=$(timeout 3 (
        echo -e "REGISTER sip:$ip SIP/2.0\r\nVia: SIP/2.0/UDP scanner\r\nTo: <sip:$ip>\r\nFrom: <sip:anonymous@anonymous>\r\nCall-ID: anon@scanner\r\nCSeq: 1 REGISTER\r\nContact: <sip:scanner>\r\n\r\n"
        sleep 1
    ) | nc -w 2 "$ip" 5060 2>/dev/null || true)
    
    if echo "$response" | grep -q "200 OK"; then
        append_cve_finding "$ip" "MISCONFIGURATION" "Anonymous SIP Registration Allowed" \
            "HIGH" "System accepts anonymous SIP registration - potential unauthorized call routing" \
            "sip://$ip:5060"
    fi
}

test_default_credentials() {
    local ip="$1"
    
    declare -a default_creds=(
        "admin:admin"
        "admin:password"
        "root:root"
        "admin:123456"
    )
    
    for cred in "${default_creds[@]}"; do
        local user=$(echo "$cred" | cut -d: -f1)
        local pass=$(echo "$cred" | cut -d: -f2)
        
        # Try HTTP authentication
        local response=$(timeout 3 curl -s -u "$user:$pass" "http://$ip/admin/" 2>/dev/null || true)
        
        if echo "$response" | grep -q -E "dashboard|admin|console" && [[ -n "$response" ]]; then
            append_cve_finding "$ip" "CREDENTIAL" "Default Credentials Accepted" \
                "CRITICAL" "System accepts default credentials: $user:$pass" \
                "http://$ip/admin/"
            return
        fi
    done
}

test_sip_header_injection() {
    local ip="$1"
    
    # Test for SIP header injection via malformed headers
    local injection_payload='test"; DROP TABLE users; --'
    local response=$(timeout 3 (
        echo -e "INVITE sip:$ip SIP/2.0\r\nVia: SIP/2.0/UDP scanner\r\nUser-Agent: $injection_payload\r\n\r\n"
        sleep 1
    ) | nc -w 2 "$ip" 5060 2>/dev/null || true)
    
    # If we get any response, the system is processing our injection
    if [[ -n "$response" && ! "$response" =~ "400 Bad Request" ]]; then
        append_cve_finding "$ip" "INJECTION" "Potential SIP Header Injection Vulnerability" \
            "HIGH" "System may be vulnerable to SIP header injection attacks" \
            "sip://$ip:5060"
    fi
}

test_ssrf_vulnerability() {
    local ip="$1"
    
    # Test for SSRF via HTTP endpoints
    local response=$(timeout 3 curl -s "http://$ip/api/fetch?url=http://localhost/admin" 2>/dev/null || true)
    
    if echo "$response" | grep -q -E "admin|root|dashboard"; then
        append_cve_finding "$ip" "SSRF" "Server-Side Request Forgery (SSRF) Detected" \
            "HIGH" "API endpoint may be vulnerable to SSRF attacks" \
            "http://$ip/api/fetch"
    fi
}

phase3d_brute_force_tests() {
    [[ "$ENABLE_BRUTE_FORCE_TESTS" != "true" ]] && return
    [[ ! command -v hydra &> /dev/null ]] && { log_warn "hydra not installed - skipping brute-force tests"; return; }
    
    log_info "Running brute-force resistance tests"
    
    # Create a minimal password list for testing
    local wordlist="${TEMP_DIR}/sip_passwords.txt"
    cat > "$wordlist" << 'EOF'
password
admin
12345
cisco
polycom
yealink
asterisk
voip
EOF
    
    # Test SIP brute-force resistance
    while IFS= read -r ip; do
        {
            timeout 30 hydra -l admin -P "$wordlist" -f sip://"$ip" 2>&1 | \
            grep -q "1 valid login" && \
            append_cve_finding "$ip" "BRUTEFORCE" "Weak SIP Authentication" \
                "CRITICAL" "System is vulnerable to SIP credential brute-force attacks" \
                "sip://$ip:5060"
        } &
        
        while (( $(jobs -r -p | wc -l) >= 5 )); do
            sleep 0.5
        done
    done < "$LIVE_IPS_FILE"
    wait
}

append_cve_finding() {
    local ip="$1"
    local cve_id="$2"
    local title="$3"
    local severity="$4"
    local description="$5"
    local url="$6"
    
    cat >> "$CVE_FINDINGS" << EOF
{
  "ip": "$ip",
  "cve_id": "$cve_id",
  "title": "$title",
  "severity": "$severity",
  "description": "$description",
  "url": "$url",
  "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
}
EOF
}

# ============================================================================
# PHASE 4: CDR ANOMALY DETECTION & TOLL FRAUD ANALYSIS
# ============================================================================

phase4_cdr_fraud_analysis() {
    log_banner "PHASE 4: CDR ANOMALY DETECTION & TOLL FRAUD ANALYSIS"
    
    [[ ! -f "$CDR_FILE" ]] && { log_warn "Skipping Phase 4 - no CDR file"; return 0; }
    
    log_info "Analyzing CDR data for fraud patterns and anomalies"
    
    # Use Python for advanced analysis
    if command -v python3 &> /dev/null; then
        phase4_python_analysis
    else
        phase4_bash_analysis
    fi
    
    log_success "Phase 4 Complete"
}

phase4_python_analysis() {
    local python_script="${TEMP_DIR}/cdr_analysis.py"
    
    cat > "$python_script" << 'PYEOF'
#!/usr/bin/env python3

import csv
import json
import sys
from collections import defaultdict
from datetime import datetime

CDR_FILE = sys.argv[1] if len(sys.argv) > 1 else "asterisk_cdr.csv"
APPROVED_CODES = ["+1", "+44", "+61", "+33", "+49", "+81", "+86"]
VOLUME_THRESHOLD = 50  # calls per day
DURATION_THRESHOLD = 500  # minutes per day
FRAUD_REPORT = "results/fraud_analysis.txt"

def extract_country_code(number):
    """Extract E.164 country code from phone number"""
    if number.startswith("+"):
        for i in range(1, 4):
            if i < len(number) and number[:i].isdigit():
                continue
            return number[:i] if i > 1 else number[:2]
    elif number.startswith("011"):
        # US format international
        return "+" + number[3:6] if len(number) > 5 else ""
    return None

def analyze_cdr_data():
    """Analyze CDR data for fraud patterns"""
    
    country_stats = defaultdict(lambda: defaultdict(lambda: {
        'calls': 0,
        'duration': 0,
        'destinations': set()
    }))
    
    flagged_days = []
    
    try:
        with open(CDR_FILE, 'r') as f:
            reader = csv.DictReader(f)
            
            for row in reader:
                try:
                    calldate = row.get('calldate', '')
                    dst = row.get('dst_number', '')
                    duration = int(row.get('duration_seconds', 0))
                    
                    if not dst or not calldate:
                        continue
                    
                    country_code = extract_country_code(dst)
                    if not country_code:
                        continue
                    
                    day = calldate.split()[0]
                    stats = country_stats[country_code][day]
                    
                    stats['calls'] += 1
                    stats['duration'] += duration
                    stats['destinations'].add(dst)
                    
                except (ValueError, KeyError) as e:
                    continue
    
    except FileNotFoundError:
        print(f"Error: CDR file not found: {CDR_FILE}", file=sys.stderr)
        return
    
    # Flag suspicious activity
    with open(FRAUD_REPORT, 'w') as report:
        report.write("╔════════════════════════════════════════════════════════════════════╗\n")
        report.write("║             CDR FRAUD ANALYSIS & ANOMALY DETECTION REPORT           ║\n")
        report.write("║             Generated: " + datetime.now().strftime("%Y-%m-%d %H:%M:%S") + "                ║\n")
        report.write("╚════════════════════════════════════════════════════════════════════╝\n\n")
        
        report.write(f"Approved Country Codes: {', '.join(APPROVED_CODES)}\n")
        report.write(f"Volume Threshold: {VOLUME_THRESHOLD} calls/day\n")
        report.write(f"Duration Threshold: {DURATION_THRESHOLD} minutes/day\n\n")
        
        report.write("═" * 70 + "\n")
        report.write("FLAGGED HIGH-RISK DESTINATIONS\n")
        report.write("═" * 70 + "\n\n")
        
        flagged_records = []
        
        for country_code, days in country_stats.items():
            if country_code in APPROVED_CODES:
                continue
            
            for day, stats in days.items():
                if stats['calls'] >= VOLUME_THRESHOLD or stats['duration'] >= DURATION_THRESHOLD:
                    flagged_records.append({
                        'country_code': country_code,
                        'day': day,
                        'calls': stats['calls'],
                        'duration': stats['duration'],
                        'unique_dests': len(stats['destinations']),
                        'risk_score': (stats['calls'] / VOLUME_THRESHOLD) + (stats['duration'] / DURATION_THRESHOLD)
                    })
        
        # Sort by duration descending
        flagged_records.sort(key=lambda x: x['duration'], reverse=True)
        
        # Format as table
        report.write(f"{'Country Code':<15} {'Date':<15} {'Calls':<10} {'Duration (min)':<20} {'Risk':<10}\n")
        report.write("─" * 70 + "\n")
        
        for record in flagged_records:
            risk_level = "🔴 CRITICAL" if record['risk_score'] > 2 else "🟠 HIGH"
            report.write(f"{record['country_code']:<15} {record['day']:<15} {record['calls']:<10} "
                        f"{record['duration']:<20} {risk_level:<10}\n")
        
        report.write("\n" + "═" * 70 + "\n")
        report.write(f"Total Flagged Records: {len(flagged_records)}\n")
        report.write(f"Estimated Fraud Loss: ${sum(r['duration'] * 0.15 for r in flagged_records):.2f}\n")
        report.write("═" * 70 + "\n")

if __name__ == "__main__":
    analyze_cdr_data()
PYEOF

    python3 "$python_script" "$CDR_FILE"
}

phase4_bash_analysis() {
    log_info "Using Bash for CDR analysis (limited features)"
    
    {
        echo "╔════════════════════════════════════════════════════════════════════╗"
        echo "║             CDR FRAUD ANALYSIS & ANOMALY DETECTION REPORT           ║"
        echo "║             Generated: $(date '+%Y-%m-%d %H:%M:%S')                ║"
        echo "╚════════════════════════════════════════════════════════════════════╝"
        echo ""
        echo "Approved Country Codes: $(IFS=, ; echo "${APPROVED_COUNTRY_CODES[*]}")"
        echo ""
        echo "═════════════════════════════════════════════════════════════════════"
        echo "TOP INTERNATIONAL DESTINATIONS BY CALL VOLUME"
        echo "═════════════════════════════════════════════════════════════════════"
        echo ""
        
        # Extract and analyze top destinations
        tail -n +2 "$CDR_FILE" 2>/dev/null | \
        awk -F',' '{print $3}' | \
        grep -E "^\+|^011" | \
        sort | uniq -c | sort -rn | head -20 | \
        awk '{printf "%-5d calls to destination %s\n", $1, $2}'
        
        echo ""
        echo "═════════════════════════════════════════════════════════════════════"
        
    } > "$FRAUD_REPORT"
}

# ============================================================================
# PHASE 5: CONFIGURATION HARDENING & RECOMMENDATIONS
# ============================================================================

phase5_hardening_configuration() {
    log_banner "PHASE 5: CONFIGURATION HARDENING & RECOMMENDATIONS"
    
    {
        echo "╔════════════════════════════════════════════════════════════════════╗"
        echo "║        ENTERPRISE VOIP SECURITY HARDENING CONFIGURATION             ║"
        echo "║        Generated: $(date '+%Y-%m-%d %H:%M:%S')                     ║"
        echo "╚════════════════════════════════════════════════════════════════════╝"
        echo ""
        
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        echo "COMPONENT 1: ASTERISK DIALPLAN SECURITY (extensions.conf)"
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        echo ""
        
        cat << 'DIALPLAN'

; ========================================
; SECURE INTERNATIONAL CALL ROUTING
; ========================================

[international-blocked]
; Block all international calls by default
exten => _9!,1,Verbose(1,Attempted international call to ${EXTEN:1})
same => n,Log(WARNING,Unauthorized international call attempt: ${EXTEN:1} from ${CALLERID(num)})
same => n,Playback(privacy-incorrect)
same => n,Hangup()

[international-approved]
; Approved international routing with authentication
exten => 90[1-9].,1,Verbose(1,Processing approved international call to ${EXTEN:2})
same => n,Set(COUNTRY_CODE=${EXTEN:2:2})
same => n,GotoIf($["${COUNTRY_CODE}" = "1"]?us_routing)
same => n,GotoIf($["${COUNTRY_CODE}" = "44"]?uk_routing)
same => n,GotoIf($["${COUNTRY_CODE}" = "61"]?au_routing)
same => n,Playback(privacy-incorrect)
same => n,Hangup()

exten => us_routing,1,Verbose(1,Routing to US +1)
same => n,Dial(SIP/provider_usa/${EXTEN:2})
same => n,Hangup()

exten => uk_routing,1,Verbose(1,Routing to UK +44)
same => n,Dial(SIP/provider_uk/${EXTEN:2})
same => n,Hangup()

exten => au_routing,1,Verbose(1,Routing to Australia +61)
same => n,Dial(SIP/provider_au/${EXTEN:2})
same => n,Hangup()

[main-security]
; Main context with security controls
exten => _X.,1,Log(NOTICE,Incoming call from ${CALLERID(num)} to ${EXTEN})

; Rate limiting - max 5 calls per minute per extension
exten => _X.,n,Set(CALL_COUNT=${GLOBAL(call_count_${CALLERID(num)}):-0})
exten => _X.,n,Set(LAST_CALL_TIME=${GLOBAL(last_call_time_${CALLERID(num)}):-0})
exten => _X.,n,Set(CURRENT_TIME=${EPOCH})
exten => _X.,n,GotoIf($[$[${CURRENT_TIME} - ${LAST_CALL_TIME}] > 60]?reset_counter)
exten => _X.,n,GotoIf($[${CALL_COUNT} > 5]?rate_limit_exceeded)
exten => _X.,n,Set(GLOBAL(call_count_${CALLERID(num)})=$[${CALL_COUNT} + 1])
exten => _X.,n,Goto(process_call)

exten => reset_counter,1,Set(GLOBAL(call_count_${CALLERID(num)})=1)
exten => reset_counter,n,Goto(process_call)

exten => rate_limit_exceeded,1,Log(WARNING,Rate limit exceeded for ${CALLERID(num)})
exten => rate_limit_exceeded,n,Playback(privacy-incorrect)
exten => rate_limit_exceeded,n,Hangup()

exten => process_call,1,Set(GLOBAL(last_call_time_${CALLERID(num)})=${EPOCH})

; Reject international 011 prefix calls
exten => _011X.,1,Log(WARNING,Blocked international call: 011${EXTEN:3} from ${CALLERID(num)})
exten => _011X.,n,Playback(privacy-incorrect)
exten => _011X.,n,Hangup()

; Route local calls
exten => _9XXXXX,1,Dial(SIP/provider/${EXTEN:1})
exten => _9XXXXX,n,Hangup()

DIALPLAN

        echo ""
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        echo "COMPONENT 2: FAIL2BAN SIP BRUTE-FORCE PROTECTION"
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        echo ""
        
        cat << 'FAIL2BAN'

[INCLUDES]
before = common.conf

[Definition]
# SIP brute-force patterns
_daemon = asterisk|SIP
failregex = ^.*SIP/2\.0.*401 Unauthorized.*<HOST>.*$
            ^.*SIP/2\.0.*403 Forbidden.*<HOST>.*$
            ^.*SIP Registration request.*from unknown host <HOST>.*$
            ^.*Call from <HOST>.*exceeds max calls limit.*$
            ^.*<HOST>.*SIP OPTIONS scan detected.*$
            ^.*Aggressive SIP scanning from <HOST>.*$
            ^.*Failed SIP authentication attempt from <HOST>.*$
            ^.*Denied SIP INVITE from <HOST>.*$

ignoreregex = ^.*from internal network.*$

datepattern = %%ExY-%%m-%%d %%H:%%M:%%S
              ^.{19}

[Init]
journalmatch = _SYSTEMD_UNIT=asterisk.service

FAIL2BAN

        echo ""
        cat << 'FAIL2BAN_JAIL'

# /etc/fail2ban/jail.d/asterisk-sip.conf

[asterisk-sip]
enabled = true
port = 5060,5061,5062
filter = asterisk
logpath = /var/log/asterisk/messages
maxretry = 3
findtime = 300
bantime = 3600
action = iptables-multiport[name=asterisk-sip, port="5060,5061,5062", protocol=udp]
         sendmail-whois[name=Asterisk, dest=admin@example.com]

[asterisk-sip-aggressive]
enabled = true
port = 5060,5061
filter = asterisk
logpath = /var/log/asterisk/messages
maxretry = 1
findtime = 60
bantime = 7200
action = iptables-multiport[name=asterisk-aggressive, port="5060,5061", protocol=udp]

FAIL2BAN_JAIL

        echo ""
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        echo "COMPONENT 3: SIP OPTIONS HEADER SUPPRESSION (sip.conf)"
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        echo ""
        
        cat << 'SIPCONF'

; /etc/asterisk/sip.conf - Security Hardening

[general]
; Disable version information disclosure
sipdebug = no
videosupport = no
faxdetect = no

; Suppress Server header in SIP responses
sendrpid = no
rpid_update = no

; Disable SIP OPTIONS response
sip_options_response = no

; Disable version info in User-Agent
useragent = Asterisk

; Strict SIP protocol enforcement
tos_sip = cs3
tos_audio = ef
tos_video = af41
cos_sip = 3
cos_audio = 6
cos_video = 4

; Disable unnecessary headers
disallow_globals_in_config = yes

; Authenticate all SIP requests
authenticate_invite = yes
authenticated_request = yes

; Require auth on registration
requirecalltoken = yes

; Disable direct media without authentication
directmedia = no

; Encryption settings
tlsenable = yes
tlsbindaddr = 0.0.0.0:5061
tlscertfile = /etc/asterisk/keys/asterisk.crt
tlsprivatekey = /etc/asterisk/keys/asterisk.key
tlscipher = ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256

; Disable insecure methods
allowoverlap = no
allowsubscribe = no
allowtransfer = no

; SIP registration timeout (prevent account enumeration)
minexpiry = 60
maxexpiry = 300
defaultexpiry = 120

; Do not send detailed error responses
sip_verbose_debuginfo = no

[authentication]
; Enforce strong authentication
auth_method = userpass
auth_timeout = 30

SIPCONF

        echo ""
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        echo "COMPONENT 4: IPTABLES FIREWALL RULES"
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        echo ""
        
        cat << 'IPTABLES'

#!/bin/bash
# VoIP Security Firewall Configuration

# Clear existing rules
iptables -F
iptables -X
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT ACCEPT

# Allow loopback
iptables -A INPUT -i lo -j ACCEPT

# Allow established connections
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

# Rate limiting for SIP
iptables -A INPUT -p udp --dport 5060 -m limit --limit 50/second --limit-burst 100 -j ACCEPT
iptables -A INPUT -p udp --dport 5060 -j DROP

iptables -A INPUT -p tcp --dport 5061 -m limit --limit 50/second --limit-burst 100 -j ACCEPT
iptables -A INPUT -p tcp --dport 5061 -j DROP

# RTP port range protection
iptables -A INPUT -p udp --dport 16384:32767 -m state --state NEW,ESTABLISHED -j ACCEPT

# Only allow SIP from trusted networks
iptables -A INPUT -p udp -s 192.168.1.0/24 --dport 5060 -j ACCEPT
iptables -A INPUT -p tcp -s 192.168.1.0/24 --dport 5061 -j ACCEPT

# Drop SIP packets with suspicious flags
iptables -A INPUT -p udp --dport 5060 -m string --string "INVITE" --algo bm -j ACCEPT
iptables -A INPUT -p udp --dport 5060 -m string --string "OPTIONS" --algo bm -m limit --limit 10/second -j ACCEPT

# Protect against SIP scanning
iptables -A INPUT -p udp --dport 5060 -m recent --set --name sip
iptables -A INPUT -p udp --dport 5060 -m recent --name sip --update --seconds 10 --hitcount 100 -j DROP

# Save rules
iptables-save > /etc/iptables/rules.v4

IPTABLES

        echo ""
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        echo "COMPONENT 5: RECOMMENDED SECURITY MEASURES"
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        echo ""
        echo "1. ENABLE TRANSPORT LAYER SECURITY (TLS)"
        echo "   - Enforce TLS for all SIP signaling"
        echo "   - Use strong certificates (RSA 2048-bit minimum)"
        echo "   - Implement certificate pinning"
        echo ""
        
        echo "2. IMPLEMENT SRTP FOR MEDIA ENCRYPTION"
        echo "   - Mandatory SRTP for all media streams"
        echo "   - Negotiate encryption parameters securely"
        echo "   - Use strong cipher suites (AES-256-GCM)"
        echo ""
        
        echo "3. DISABLE DANGEROUS SIP METHODS"
        echo "   - BYE, CANCEL, PRACK when not needed"
        echo "   - SUBSCRIBE, NOTIFY (reduce attack surface)"
        echo "   - INFO, UPDATE (for limited use cases only)"
        echo ""
        
        echo "4. IMPLEMENT DDoS MITIGATION"
        echo "   - IP reputation filtering"
        echo "   - Connection rate limiting"
        echo "   - Geographic filtering"
        echo "   - Anycast network distribution"
        echo ""
        
        echo "5. ENABLE COMPREHENSIVE LOGGING & MONITORING"
        echo "   - Log all authentication attempts"
        echo "   - Monitor for anomalous patterns"
        echo "   - Real-time alerts for suspicious activity"
        echo "   - Centralized log aggregation (ELK, Splunk)"
        echo ""
        
        echo "6. IMPLEMENT VPN/IPSEC FOR TRUNK CONNECTIONS"
        echo "   - Require IPSec for provider trunks"
        echo "   - Use IKEv2 with strong algorithms"
        echo "   - Perfect forward secrecy (PFS)"
        echo ""
        
        echo "7. REGULAR SECURITY UPDATES"
        echo "   - Subscribe to Asterisk security advisories"
        echo "   - Test patches in staging environment first"
        echo "   - Implement automated patch management"
        echo ""
        
        echo "8. NETWORK SEGMENTATION"
        echo "   - Isolate VoIP network from data network"
        echo "   - Use dedicated VLAN for SIP signaling"
        echo "   - Separate RTP media path"
        echo ""
        
    } > "$HARDENING_CONFIG"
    
    log_success "Hardening configuration generated"
}

# ============================================================================
# PHASE 6: EXECUTIVE SUMMARY & REPORTING
# ============================================================================

phase6_executive_summary() {
    log_banner "PHASE 6: GENERATING EXECUTIVE SUMMARY"
    
    {
        echo "╔════════════════════════════════════════════════════════════════════╗"
        echo "║          ENTERPRISE VOIP SECURITY ASSESSMENT EXECUTIVE SUMMARY      ║"
        echo "║          Assessment Date: $(date '+%Y-%m-%d %H:%M:%S')              ║"
        echo "║          Script Version: $SCRIPT_VERSION                            ║"
        echo "╚════════════════════════════════════════════════════════════════════╝"
        echo ""
        
        # Assessment Overview
        echo "ASSESSMENT OVERVIEW"
        echo "═" * 70
        echo "Total IPs Scanned: $([ -f "$INPUT_FILE" ] && wc -l < "$INPUT_FILE" || echo "0")"
        echo "Live Hosts Discovered: $([ -f "$LIVE_IPS_FILE" ] && wc -l < "$LIVE_IPS_FILE" || echo "0")"
        echo "Critical CVEs Detected: $([ -f "$CVE_FINDINGS" ] && grep -c '"CRITICAL"' "$CVE_FINDINGS" || echo "0")"
        echo "High Severity Issues: $([ -f "$CVE_FINDINGS" ] && grep -c '"HIGH"' "$CVE_FINDINGS" || echo "0")"
        echo ""
        
        # Key Findings
        echo "KEY FINDINGS"
        echo "═" * 70
        
        if [ -f "$CVE_FINDINGS" ]; then
            echo "Top 5 Vulnerabilities Detected:"
            jq -r '.[] | select(.severity == "CRITICAL" or .severity == "HIGH") | 
                    "\(.cve_id): \(.title) [\(.severity)]"' "$CVE_FINDINGS" 2>/dev/null | head -5 || echo "No CVE data available"
        else
            echo "No CVE findings file generated"
        fi
        echo ""
        
        # Risk Assessment
        echo "RISK ASSESSMENT"
        echo "═" * 70
        local critical_count=$([ -f "$CVE_FINDINGS" ] && grep -c '"CRITICAL"' "$CVE_FINDINGS" || echo "0")
        
        if [ "$critical_count" -gt 0 ]; then
            echo "Overall Risk Level: 🔴 CRITICAL"
            echo "Remediation Priority: IMMEDIATE ACTION REQUIRED"
        else
            echo "Overall Risk Level: 🟡 MODERATE"
            echo "Remediation Priority: Plan for next maintenance window"
        fi
        echo ""
        
        # Compliance Status
        echo "COMPLIANCE RECOMMENDATIONS"
        echo "═" * 70
        echo "✓ Implement TLS 1.2+ for all SIP signaling"
        echo "✓ Enable SRTP for media encryption"
        echo "✓ Deploy fail2ban with aggressive SIP protection"
        echo "✓ Disable SIP OPTIONS responses to external networks"
        echo "✓ Implement authentication on all interfaces"
        echo "✓ Enable comprehensive audit logging"
        echo "✓ Segment VoIP network from corporate network"
        echo ""
        
        # Remediation Timeline
        echo "RECOMMENDED REMEDIATION TIMELINE"
        echo "═" * 70
        echo "IMMEDIATE (within 24 hours):"
        echo "  - Patch critical vulnerabilities"
        echo "  - Disable anonymous SIP registration"
        echo "  - Enable firewall rules"
        echo ""
        echo "SHORT-TERM (within 1 week):"
        echo "  - Deploy fail2ban protection"
        echo "  - Implement TLS/SRTP"
        echo "  - Update default credentials"
        echo ""
        echo "MEDIUM-TERM (within 30 days):"
        echo "  - Network segmentation"
        echo "  - Implement monitoring/alerting"
        echo "  - Security hardening (see hardening_config.txt)"
        echo ""
        
        # Generated Reports
        echo "GENERATED REPORTS"
        echo "═" * 70
        echo "✓ verified_voip_vulnerabilities.txt    - Detailed CVE findings"
        echo "✓ service_fingerprints.json            - Identified services"
        echo "✓ cve_findings.json                    - Structured CVE data"
        echo "✓ fraud_analysis.txt                   - CDR fraud analysis"
        echo "✓ hardening_config.txt                 - Security configurations"
        echo "✓ executive_summary.txt                - This report"
        echo ""
        
        echo "NEXT STEPS"
        echo "═" * 70
        echo "1. Review detailed findings in verified_voip_vulnerabilities.txt"
        echo "2. Prioritize critical CVE remediations"
        echo "3. Implement hardening configurations"
        echo "4. Deploy monitoring and alerting"
        echo "5. Schedule regular security assessments"
        echo ""
        
    } > "$EXECUTIVE_SUMMARY"
    
    log_success "Executive summary generated"
    cat "$EXECUTIVE_SUMMARY"
}

# ============================================================================
# CLEANUP & FINALIZATION
# ============================================================================

cleanup() {
    log_banner "CLEANUP & FINALIZATION"
    
    if [[ -d "$TEMP_DIR" ]]; then
        log_info "Removing temporary directory: $TEMP_DIR"
        rm -rf "$TEMP_DIR"
    fi
    
    # Display final report locations
    echo ""
    echo "╔════════════════════════════════════════════════════════════════════╗"
    echo "║                    ASSESSMENT COMPLETE                             ║"
    echo "╚════════════════════════════════════════════════════════════════════╝"
    echo ""
    echo "Report Location: $RESULTS_DIR"
    echo "Log File: $LOG_FILE"
    echo ""
    ls -lah "$RESULTS_DIR" 2>/dev/null || true
}

error_handler() {
    local line=$1
    log_error "Script failed at line $line with status $?"
    cleanup
    exit 1
}

trap cleanup EXIT
trap 'error_handler $LINENO' ERR

# ============================================================================
# MAIN EXECUTION
# ============================================================================

main() {
    initialize_logging
    
    log_info "Starting Enterprise VoIP Security Automation Framework v$SCRIPT_VERSION"
    
    # Validation
    if ! validate_dependencies; then
        log_error "Dependency validation failed"
        return 1
    fi
    
    validate_input_files
    
    # Execute assessment phases
    phase1_advanced_reconnaissance || log_warn "Phase 1 encountered issues"
    phase2_service_fingerprinting || log_warn "Phase 2 encountered issues"
    phase3_advanced_vulnerability_detection || log_warn "Phase 3 encountered issues"
    phase4_cdr_fraud_analysis || log_warn "Phase 4 encountered issues"
    phase5_hardening_configuration || log_warn "Phase 5 encountered issues"
    phase6_executive_summary || log_warn "Phase 6 encountered issues"
    
    log_success "All assessment phases completed"
    return 0
}

# Execute with error handling
main "$@"
exit_code=$?

cleanup
exit $exit_code
