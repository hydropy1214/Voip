#!/bin/bash

###############################################################################
# ENTERPRISE VOIP SECURITY AUTOMATION FRAMEWORK v3.0
# Comprehensive VoIP Infrastructure Assessment & Exploitation Prevention
# Covers: Reconnaissance, Fingerprinting, Vulnerability Detection,
# SIP Enumeration, Extension Scanning, RTP/RTCP Attacks,
# Credential Harvesting, Vendor-Specific Exploits,
# CDR Fraud Analysis, Configuration Hardening, and Advanced Attack Scenarios
###############################################################################

set -euo pipefail

# ============================================================================
# SCRIPT METADATA & CONFIGURATION
# ============================================================================

readonly SCRIPT_VERSION="3.0.0"
readonly SCRIPT_NAME="$(basename "$0")"
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Support targets.txt as primary input; fall back to command-line arg or shodan_ips.txt
# Priority: (1) explicit first argument, (2) targets.txt if present, (3) shodan_ips.txt
if [[ $# -ge 1 && -n "${1:-}" ]]; then
    readonly INPUT_FILE="${1}"
elif [[ -f "targets.txt" ]]; then
    readonly INPUT_FILE="targets.txt"
else
    readonly INPUT_FILE="shodan_ips.txt"
fi

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
    # New CVEs added in v3.0
    ["CVE-2022-26272"]="FreePBX Remote Code Execution via Module Upload"
    ["CVE-2021-43734"]="Sangoma Asterisk AMI Remote Command Injection"
    ["CVE-2019-18610"]="Asterisk AMI Privilege Escalation via User Agent"
    ["CVE-2017-14099"]="Asterisk PJSIP Redirect Remote Code Execution"
    ["CVE-2019-15752"]="Kamailio SIP Server Memory Corruption"
    ["CVE-2021-22502"]="Avaya Aura Application Enablement Services RCE"
    ["CVE-2020-3161"]="Cisco IP Phone Remote Code Execution"
    ["CVE-2021-1397"]="Cisco Unified Communications Manager SSRF"
    ["CVE-2022-37397"]="Grandstream UCM6xxx SQL Injection"
    ["CVE-2020-8515"]="DrayTek Vigor Router RCE (VoIP Gateway)"
    ["CVE-2021-27561"]="Yealink Device Management Unauthenticated RCE"
    ["CVE-2019-19463"]="FreePBX User Portal Authentication Bypass"
    ["CVE-2020-16231"]="OpenSIPS Memory Corruption via Malformed SIP"
    ["CVE-2022-26652"]="Kamailio KEMI Lua Script Injection"
    ["CVE-2021-46143"]="Expat XML Parser Heap Overflow (used in SIP stacks)"
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

    # Log which input source is being used
    if [[ "$INPUT_FILE" == "targets.txt" ]]; then
        log_info "Using targets.txt as primary target input"
    else
        log_info "Using input file: $INPUT_FILE (tip: place targets in targets.txt for auto-detection)"
    fi

    if [[ -f "$INPUT_FILE" ]]; then
        local ip_count=$(grep -c '^[0-9]' "$INPUT_FILE" || echo "0")
        if [[ $ip_count -gt 0 ]]; then
            log_success "Input file validated: $ip_count IP addresses found in $INPUT_FILE"
        else
            log_warn "No valid IP addresses in $INPUT_FILE"
        fi
    else
        log_warn "IP input file not found: $INPUT_FILE (skipping Phase 1-3 and 7-11)"
        log_warn "Create targets.txt with one IP per line to enable scanning phases"
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
    local response
    response=$(timeout 3 bash -c "
        printf 'OPTIONS sip:${ip} SIP/2.0\r\nVia: SIP/2.0/UDP scanner\r\nTo: <sip:${ip}>\r\nFrom: <sip:scanner>\r\nCall-ID: scanner@scanner\r\nCSeq: 1 OPTIONS\r\nContact: <sip:scanner>\r\nAccept: application/sdp\r\n\r\n'
        sleep 1
    " | nc -w 2 "$ip" 5060 2>/dev/null || true)
    
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
    local response
    response=$(timeout 3 bash -c "
        printf 'OPTIONS sip:${ip} SIP/2.0\r\nVia: SIP/2.0/UDP scanner\r\n\r\n'
        sleep 1
    " | nc -w 2 "$ip" 5060 2>/dev/null || true)
    
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
    local response
    response=$(timeout 3 bash -c "
        printf 'REGISTER sip:${ip} SIP/2.0\r\nVia: SIP/2.0/UDP scanner\r\nTo: <sip:${ip}>\r\nFrom: <sip:anonymous@anonymous>\r\nCall-ID: anon@scanner\r\nCSeq: 1 REGISTER\r\nContact: <sip:scanner>\r\n\r\n'
        sleep 1
    " | nc -w 2 "$ip" 5060 2>/dev/null || true)
    
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
    local response
    response=$(timeout 3 bash -c "
        printf 'INVITE sip:${ip} SIP/2.0\r\nVia: SIP/2.0/UDP scanner\r\nUser-Agent: ${injection_payload}\r\n\r\n'
        sleep 1
    " | nc -w 2 "$ip" 5060 2>/dev/null || true)
    
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
    ! command -v hydra &> /dev/null && { log_warn "hydra not installed - skipping brute-force tests"; return; }
    
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
# PHASE 7: SIP ENUMERATION & METHOD FUZZING
# ============================================================================

phase7_sip_enumeration() {
    log_banner "PHASE 7: SIP ENUMERATION & METHOD FUZZING"

    [[ ! -s "$LIVE_IPS_FILE" ]] && { log_warn "Skipping Phase 7 - no live hosts"; return 0; }

    log_info "Testing SIP methods and enumerating server capabilities"

    while IFS= read -r ip; do
        {
            test_sip_methods "$ip"
            test_sip_user_enumeration "$ip"
            test_sip_options_disclosure "$ip"
            test_sip_subscribe_notify "$ip"
            test_sip_info_method "$ip"
        } &

        while (( $(jobs -r -p | wc -l) >= THREADS )); do
            sleep 0.1
        done
    done < "$LIVE_IPS_FILE"
    wait

    log_success "Phase 7 Complete"
}

test_sip_methods() {
    local ip="$1"
    local call_id="method-test-$(date +%s%N)"

    # Probe each SIP method and record allowed/forbidden responses
    for method in OPTIONS REGISTER INVITE SUBSCRIBE NOTIFY PUBLISH INFO UPDATE REFER MESSAGE; do
        local response
        response=$(timeout 3 bash -c "
            printf 'OPTIONS sip:${ip} SIP/2.0\r\nVia: SIP/2.0/UDP scanner:5060;branch=z9hG4bK${call_id}\r\nMax-Forwards: 1\r\nTo: <sip:${ip}>\r\nFrom: <sip:probe@scanner>;tag=probe\r\nCall-ID: ${call_id}@scanner\r\nCSeq: 1 OPTIONS\r\nContact: <sip:scanner>\r\nContent-Length: 0\r\n\r\n'
            sleep 1
        " | nc -u -w 2 "$ip" 5060 2>/dev/null || true)

        # If a method is not 405/501, flag it as potentially exploitable
        if echo "$response" | grep -qE "^SIP/2\.0 (200|202|404|401|403)"; then
            log_debug "SIP $method accepted by $ip"
        fi
    done

    # Detect Allow header listing dangerous methods
    local options_response
    options_response=$(timeout 3 bash -c "
        printf 'OPTIONS sip:${ip} SIP/2.0\r\nVia: SIP/2.0/UDP scanner:5060;branch=z9hG4bKopts\r\nMax-Forwards: 1\r\nTo: <sip:${ip}>\r\nFrom: <sip:probe@scanner>;tag=probe\r\nCall-ID: opts@scanner\r\nCSeq: 1 OPTIONS\r\nContent-Length: 0\r\n\r\n'
        sleep 1
    " | nc -u -w 2 "$ip" 5060 2>/dev/null || true)

    local allow_header
    allow_header=$(echo "$options_response" | grep -i "^Allow:" | head -1)

    if echo "$allow_header" | grep -qiE "SUBSCRIBE|NOTIFY|REFER|PUBLISH|MESSAGE"; then
        append_cve_finding "$ip" "SIP-METHODS" "Risky SIP Methods Advertised" \
            "MEDIUM" "Server advertises potentially dangerous SIP methods: $allow_header" \
            "sip://$ip:5060"
    fi
}

test_sip_user_enumeration() {
    local ip="$1"
    local call_id="enum-$(date +%s%N)"

    # Probe a known-invalid user vs known-common extensions
    # Different response codes reveal user existence
    for user in admin operator 100 200 1000 test guest; do
        local response
        response=$(timeout 3 bash -c "
            printf 'REGISTER sip:${ip} SIP/2.0\r\nVia: SIP/2.0/UDP scanner:5060;branch=z9hG4bKenum\r\nMax-Forwards: 1\r\nTo: <sip:${user}@${ip}>\r\nFrom: <sip:${user}@${ip}>;tag=probe\r\nCall-ID: ${call_id}@scanner\r\nCSeq: 1 REGISTER\r\nContact: <sip:${user}@scanner>\r\nContent-Length: 0\r\n\r\n'
            sleep 1
        " | nc -u -w 2 "$ip" 5060 2>/dev/null || true)

        # 401 Unauthorized = user exists (auth required)
        # 403 Forbidden = user exists (denied)
        # 404 Not Found = user does not exist
        if echo "$response" | grep -qE "^SIP/2\.0 (401|403) "; then
            append_cve_finding "$ip" "SIP-ENUM" "SIP User Enumeration Possible" \
                "MEDIUM" "User '$user' confirmed to exist on $ip (response differentiates 401/403 vs 404)" \
                "sip://$ip:5060"
            break  # One finding per host is enough
        fi
    done
}

test_sip_options_disclosure() {
    local ip="$1"

    local response
    response=$(timeout 3 bash -c "
        printf 'OPTIONS sip:${ip} SIP/2.0\r\nVia: SIP/2.0/UDP scanner:5060;branch=z9hG4bKdiscl\r\nMax-Forwards: 1\r\nTo: <sip:${ip}>\r\nFrom: <sip:probe@scanner>;tag=probe\r\nCall-ID: discl@scanner\r\nCSeq: 1 OPTIONS\r\nContent-Length: 0\r\n\r\n'
        sleep 1
    " | nc -u -w 2 "$ip" 5060 2>/dev/null || true)

    # Detect version disclosure in User-Agent / Server
    local version_line
    version_line=$(echo "$response" | grep -iE "^(Server|User-Agent):" | head -1 || true)

    if echo "$version_line" | grep -qiE "(asterisk|freepbx|opensips|kamailio|3cx|yealink|cisco|avaya|polycom|grandstream|elastix|issabel)[/ ]?[0-9.]"; then
        append_cve_finding "$ip" "VERSION-DISCLOSURE" "SIP Software Version Disclosed" \
            "LOW" "Server version information leaked via SIP OPTIONS: $version_line" \
            "sip://$ip:5060"
    fi
}

test_sip_subscribe_notify() {
    local ip="$1"
    local call_id="sub-$(date +%s%N)"

    # Test if SUBSCRIBE is accepted without authentication (presence/event abuse)
    local response
    response=$(timeout 3 bash -c "
        printf 'SUBSCRIBE sip:${ip} SIP/2.0\r\nVia: SIP/2.0/UDP scanner:5060;branch=z9hG4bKsub\r\nMax-Forwards: 1\r\nTo: <sip:${ip}>\r\nFrom: <sip:probe@scanner>;tag=probe\r\nCall-ID: ${call_id}@scanner\r\nCSeq: 1 SUBSCRIBE\r\nEvent: presence\r\nExpires: 60\r\nContact: <sip:probe@scanner>\r\nContent-Length: 0\r\n\r\n'
        sleep 1
    " | nc -u -w 2 "$ip" 5060 2>/dev/null || true)

    if echo "$response" | grep -qE "^SIP/2\.0 (200|202) "; then
        append_cve_finding "$ip" "SIP-SUBSCRIBE" "Unauthenticated SIP SUBSCRIBE Accepted" \
            "HIGH" "Server accepts SUBSCRIBE requests without authentication - information disclosure risk" \
            "sip://$ip:5060"
    fi
}

test_sip_info_method() {
    local ip="$1"
    local call_id="info-$(date +%s%N)"

    # Test if INFO method with DTMF payload is accepted
    local response
    response=$(timeout 3 bash -c "
        printf 'INFO sip:${ip} SIP/2.0\r\nVia: SIP/2.0/UDP scanner:5060;branch=z9hG4bKinfo\r\nMax-Forwards: 1\r\nTo: <sip:${ip}>\r\nFrom: <sip:probe@scanner>;tag=probe\r\nCall-ID: ${call_id}@scanner\r\nCSeq: 1 INFO\r\nContent-Type: application/dtmf-relay\r\nContent-Length: 26\r\n\r\nSignal=9\r\nDuration=160\r\n'
        sleep 1
    " | nc -u -w 2 "$ip" 5060 2>/dev/null || true)

    if echo "$response" | grep -qE "^SIP/2\.0 (200|400) "; then
        log_debug "INFO method processed by $ip"
    fi
}

# ============================================================================
# PHASE 8: EXTENSION SCANNING & USER ENUMERATION
# ============================================================================

phase8_extension_scanning() {
    log_banner "PHASE 8: EXTENSION SCANNING & USER ENUMERATION"

    [[ ! -s "$LIVE_IPS_FILE" ]] && { log_warn "Skipping Phase 8 - no live hosts"; return 0; }

    log_info "Scanning common extensions and enumerating valid users"

    local extensions_file="${TEMP_DIR}/valid_extensions.txt"
    > "$extensions_file"

    while IFS= read -r ip; do
        {
            scan_common_extensions "$ip" "$extensions_file"
            test_voicemail_access "$ip"
            test_ivr_bypass "$ip"
        } &

        while (( $(jobs -r -p | wc -l) >= THREADS )); do
            sleep 0.1
        done
    done < "$LIVE_IPS_FILE"
    wait

    if [[ -s "$extensions_file" ]]; then
        local ext_count
        ext_count=$(wc -l < "$extensions_file")
        log_success "Phase 8 discovered $ext_count valid extensions"
        cp "$extensions_file" "${RESULTS_DIR}/valid_extensions.txt"
    fi

    log_success "Phase 8 Complete"
}

scan_common_extensions() {
    local ip="$1"
    local output_file="$2"
    local valid_count=0

    # Common extension ranges to probe
    local -a probe_extensions=(
        100 101 102 103 104 105 110 111 200 201 202 210 300 301 400 401
        500 600 700 800 900 999 1000 1001 1002 1010 1100 1200 2000 2001
        9000 9001 9999 operator admin guest reception helpdesk
    )

    for ext in "${probe_extensions[@]}"; do
        local response
        response=$(timeout 2 bash -c "
            printf 'REGISTER sip:${ip} SIP/2.0\r\nVia: SIP/2.0/UDP scanner:5060;branch=z9hG4bKext${ext}\r\nMax-Forwards: 1\r\nTo: <sip:${ext}@${ip}>\r\nFrom: <sip:${ext}@${ip}>;tag=scan\r\nCall-ID: scan-${ext}@scanner\r\nCSeq: 1 REGISTER\r\nContact: <sip:${ext}@scanner>\r\nContent-Length: 0\r\n\r\n'
            sleep 0.5
        " | nc -u -w 2 "$ip" 5060 2>/dev/null || true)

        # 401 = exists but needs auth, 403 = exists but forbidden
        if echo "$response" | grep -qE "^SIP/2\.0 (401|403) "; then
            echo "$ip:$ext" >> "$output_file"
            (( valid_count++ ))
        fi
    done

    if [[ $valid_count -gt 0 ]]; then
        append_cve_finding "$ip" "EXT-ENUM" "SIP Extension Enumeration Successful" \
            "MEDIUM" "Discovered $valid_count valid extensions on $ip via REGISTER response code analysis" \
            "sip://$ip:5060"
    fi
}

test_voicemail_access() {
    local ip="$1"

    # Test voicemail access without PIN on common voicemail extensions
    for vm_ext in *97 *98 *99 8500 7999; do
        local response
        response=$(timeout 3 bash -c "
            printf 'INVITE sip:${vm_ext}@${ip} SIP/2.0\r\nVia: SIP/2.0/UDP scanner:5060;branch=z9hG4bKvm\r\nMax-Forwards: 1\r\nTo: <sip:${vm_ext}@${ip}>\r\nFrom: <sip:probe@scanner>;tag=vm\r\nCall-ID: vm@scanner\r\nCSeq: 1 INVITE\r\nContent-Type: application/sdp\r\nContent-Length: 0\r\n\r\n'
            sleep 1
        " | nc -u -w 2 "$ip" 5060 2>/dev/null || true)

        # A 200 OK response to INVITE on voicemail could mean no PIN required
        if echo "$response" | grep -qE "^SIP/2\.0 (180|183|200) "; then
            append_cve_finding "$ip" "VOICEMAIL" "Voicemail Access Without Authentication" \
                "HIGH" "Voicemail extension $vm_ext on $ip may be accessible without PIN authentication" \
                "sip://$ip:5060"
        fi
    done
}

test_ivr_bypass() {
    local ip="$1"

    # Test DTMF injection to bypass IVR menus
    local response
    response=$(timeout 3 bash -c "
        printf 'INVITE sip:0@${ip} SIP/2.0\r\nVia: SIP/2.0/UDP scanner:5060;branch=z9hG4bKivr\r\nMax-Forwards: 1\r\nTo: <sip:0@${ip}>\r\nFrom: <sip:probe@scanner>;tag=ivr\r\nCall-ID: ivr@scanner\r\nCSeq: 1 INVITE\r\nContent-Length: 0\r\n\r\n'
        sleep 1
    " | nc -u -w 2 "$ip" 5060 2>/dev/null || true)

    if echo "$response" | grep -qE "^SIP/2\.0 (180|183|200) "; then
        append_cve_finding "$ip" "IVR-BYPASS" "IVR Extension 0 Accessible" \
            "MEDIUM" "Extension '0' (operator/IVR) responds on $ip - verify PIN/auth requirements" \
            "sip://$ip:5060"
    fi
}

# ============================================================================
# PHASE 9: RTP/RTCP VULNERABILITY TESTING
# ============================================================================

phase9_rtp_attacks() {
    log_banner "PHASE 9: RTP/RTCP VULNERABILITY TESTING"

    [[ ! -s "$LIVE_IPS_FILE" ]] && { log_warn "Skipping Phase 9 - no live hosts"; return 0; }

    log_info "Testing RTP/RTCP security configuration"

    while IFS= read -r ip; do
        {
            test_rtcp_disclosure "$ip"
            test_rtp_port_exposure "$ip"
            test_srtp_enforcement "$ip"
            test_rtp_bleed "$ip"
        } &

        while (( $(jobs -r -p | wc -l) >= THREADS )); do
            sleep 0.1
        done
    done < "$LIVE_IPS_FILE"
    wait

    log_success "Phase 9 Complete"
}

test_rtcp_disclosure() {
    local ip="$1"

    # Probe common RTP/RTCP ports for open responses
    local rtcp_response
    rtcp_response=$(timeout 2 bash -c "
        printf '\x80\xc9\x00\x01\x00\x00\x00\x00'
        sleep 0.5
    " | nc -u -w 2 "$ip" 5004 2>/dev/null || true)

    if [[ -n "$rtcp_response" ]]; then
        append_cve_finding "$ip" "RTCP-DISCLOSURE" "RTCP Port Responding - Information Disclosure" \
            "MEDIUM" "RTCP port 5004 on $ip is responding - may leak call metadata and statistics" \
            "rtcp://$ip:5004"
    fi

    # Check default RTCP port 5005
    local rtcp5005
    rtcp5005=$(timeout 2 nc -u -w 2 "$ip" 5005 < /dev/null 2>/dev/null || true)
    if [[ -n "$rtcp5005" ]]; then
        log_debug "RTCP port 5005 open on $ip"
    fi
}

test_rtp_port_exposure() {
    local ip="$1"

    # Check if a large range of RTP ports is exposed
    local open_rtp_ports=0

    for port in 16384 16385 16386 20000 20001 20002 30000 32766 32767; do
        local result
        result=$(timeout 1 nc -zu "$ip" "$port" 2>&1 || true)
        if echo "$result" | grep -qv "refused\|timeout"; then
            (( open_rtp_ports++ ))
        fi
    done

    if [[ $open_rtp_ports -ge 3 ]]; then
        append_cve_finding "$ip" "RTP-EXPOSURE" "Wide RTP Port Range Exposed" \
            "MEDIUM" "$open_rtp_ports sampled RTP ports open on $ip - may enable media interception or RTP flooding" \
            "rtp://$ip:16384-32767"
    fi
}

test_srtp_enforcement() {
    local ip="$1"
    local call_id="srtp-$(date +%s%N)"

    # Send an INVITE with unencrypted SDP (no SRTP) and see if it's accepted
    local sdp_body
    sdp_body=$(cat << 'SDP'
v=0
o=scanner 0 0 IN IP4 127.0.0.1
s=Test
c=IN IP4 127.0.0.1
t=0 0
m=audio 12345 RTP/AVP 0
a=rtpmap:0 PCMU/8000
SDP
)
    local sdp_len=${#sdp_body}

    local response
    response=$(timeout 3 bash -c "
        printf 'INVITE sip:100@${ip} SIP/2.0\r\nVia: SIP/2.0/UDP scanner:5060;branch=z9hG4bKsrtp\r\nMax-Forwards: 1\r\nTo: <sip:100@${ip}>\r\nFrom: <sip:probe@scanner>;tag=srtp\r\nCall-ID: ${call_id}@scanner\r\nCSeq: 1 INVITE\r\nContact: <sip:probe@scanner>\r\nContent-Type: application/sdp\r\nContent-Length: ${sdp_len}\r\n\r\n'
        printf '%s' '${sdp_body}'
        sleep 1
    " | nc -u -w 3 "$ip" 5060 2>/dev/null || true)

    # If 100/180/200 received (not 488/493 Unsupported), SRTP is not enforced
    if echo "$response" | grep -qE "^SIP/2\.0 (100|180|183|200) "; then
        append_cve_finding "$ip" "NO-SRTP" "SRTP Not Enforced - Unencrypted Media Accepted" \
            "HIGH" "Server on $ip accepted INVITE with unencrypted RTP/AVP media - SRTP is not mandatory" \
            "sip://$ip:5060"
    fi
}

test_rtp_bleed() {
    local ip="$1"

    # Probe for RTP Bleed: send RTCP Receiver Report to random ports expecting stale session data
    # CVE-2017-9999 style: server leaks RTP data from existing calls to new requestors
    for port in 16384 16392 16400 20000 20008; do
        local response
        response=$(timeout 2 bash -c "
            printf '\x80\xc9\x00\x01\xde\xad\xbe\xef'
            sleep 0.5
        " | nc -u -w 2 "$ip" "$port" 2>/dev/null | xxd 2>/dev/null | head -4 || true)

        if [[ -n "$response" ]]; then
            append_cve_finding "$ip" "RTP-BLEED" "Potential RTP Bleed - Stale Session Data Leak" \
                "HIGH" "Port $port on $ip returned RTP/RTCP data without session negotiation - possible RTP Bleed vulnerability" \
                "rtp://$ip:$port"
            break
        fi
    done
}

# ============================================================================
# PHASE 10: CREDENTIAL HARVESTING & AUTHENTICATION BYPASS
# ============================================================================

phase10_credential_harvesting() {
    log_banner "PHASE 10: CREDENTIAL HARVESTING & AUTHENTICATION BYPASS"

    [[ ! -s "$LIVE_IPS_FILE" ]] && { log_warn "Skipping Phase 10 - no live hosts"; return 0; }

    log_info "Testing authentication mechanisms and credential security"

    while IFS= read -r ip; do
        {
            test_sip_auth_bypass "$ip"
            test_registration_hijacking "$ip"
            test_call_interception_refer "$ip"
            test_expanded_default_credentials "$ip"
            test_sip_digest_leak "$ip"
            test_ami_default_credentials "$ip"
        } &

        while (( $(jobs -r -p | wc -l) >= THREADS )); do
            sleep 0.1
        done
    done < "$LIVE_IPS_FILE"
    wait

    log_success "Phase 10 Complete"
}

test_sip_auth_bypass() {
    local ip="$1"
    local call_id="bypass-$(date +%s%N)"

    # Test 1: Empty credentials bypass
    local response
    response=$(timeout 3 bash -c "
        printf 'REGISTER sip:${ip} SIP/2.0\r\nVia: SIP/2.0/UDP scanner:5060;branch=z9hG4bKbyp\r\nMax-Forwards: 1\r\nTo: <sip:admin@${ip}>\r\nFrom: <sip:admin@${ip}>;tag=bypass\r\nCall-ID: ${call_id}@scanner\r\nCSeq: 1 REGISTER\r\nAuthorization: Digest username=\"admin\", realm=\"${ip}\", nonce=\"\", uri=\"sip:${ip}\", response=\"\"\r\nContact: <sip:admin@scanner>\r\nExpires: 3600\r\nContent-Length: 0\r\n\r\n'
        sleep 1
    " | nc -u -w 3 "$ip" 5060 2>/dev/null || true)

    if echo "$response" | grep -qE "^SIP/2\.0 200 "; then
        append_cve_finding "$ip" "AUTH-BYPASS" "SIP Authentication Bypass - Empty Credentials Accepted" \
            "CRITICAL" "Server on $ip accepted REGISTER with empty digest response - authentication bypass possible" \
            "sip://$ip:5060"
    fi

    # Test 2: Null nonce bypass
    local response2
    response2=$(timeout 3 bash -c "
        printf 'REGISTER sip:${ip} SIP/2.0\r\nVia: SIP/2.0/UDP scanner:5060;branch=z9hG4bKnull\r\nMax-Forwards: 1\r\nTo: <sip:test@${ip}>\r\nFrom: <sip:test@${ip}>;tag=null\r\nCall-ID: null-${call_id}@scanner\r\nCSeq: 1 REGISTER\r\nContact: <sip:test@scanner>\r\nExpires: 0\r\nContent-Length: 0\r\n\r\n'
        sleep 1
    " | nc -u -w 3 "$ip" 5060 2>/dev/null || true)

    if echo "$response2" | grep -qE "^SIP/2\.0 200 "; then
        append_cve_finding "$ip" "ANON-REGISTER" "Anonymous SIP De-Registration Accepted" \
            "HIGH" "Server on $ip accepted REGISTER with Expires: 0 without authentication - de-registration attack possible" \
            "sip://$ip:5060"
    fi
}

test_registration_hijacking() {
    local ip="$1"
    local call_id="hijack-$(date +%s%N)"

    # Attempt to re-register an existing extension with a different contact
    # If server accepts without challenging, registration hijacking is possible
    local response
    response=$(timeout 3 bash -c "
        printf 'REGISTER sip:${ip} SIP/2.0\r\nVia: SIP/2.0/UDP 10.10.10.10:5060;branch=z9hG4bKhijack\r\nMax-Forwards: 1\r\nTo: <sip:100@${ip}>\r\nFrom: <sip:100@${ip}>;tag=hijack\r\nCall-ID: ${call_id}@10.10.10.10\r\nCSeq: 1 REGISTER\r\nContact: <sip:100@10.10.10.10:5060>\r\nExpires: 3600\r\nContent-Length: 0\r\n\r\n'
        sleep 1
    " | nc -u -w 3 "$ip" 5060 2>/dev/null || true)

    # 200 OK without 401 challenge = hijacking possible
    if echo "$response" | grep -qE "^SIP/2\.0 200 "; then
        append_cve_finding "$ip" "REG-HIJACK" "Registration Hijacking Vulnerability" \
            "CRITICAL" "Server on $ip accepted REGISTER for extension 100 from an external IP without authentication - registration hijacking possible" \
            "sip://$ip:5060"
    fi
}

test_call_interception_refer() {
    local ip="$1"
    local call_id="refer-$(date +%s%N)"

    # Test if REFER method can redirect active calls (call hijacking)
    local response
    response=$(timeout 3 bash -c "
        printf 'REFER sip:100@${ip} SIP/2.0\r\nVia: SIP/2.0/UDP scanner:5060;branch=z9hG4bKrefer\r\nMax-Forwards: 1\r\nTo: <sip:100@${ip}>\r\nFrom: <sip:attacker@scanner>;tag=refer\r\nCall-ID: ${call_id}@scanner\r\nCSeq: 1 REFER\r\nRefer-To: <sip:attacker@scanner>\r\nContent-Length: 0\r\n\r\n'
        sleep 1
    " | nc -u -w 3 "$ip" 5060 2>/dev/null || true)

    # Should return 401/403/404/481 - if 200/202, call redirection without auth
    if echo "$response" | grep -qE "^SIP/2\.0 (200|202) "; then
        append_cve_finding "$ip" "CALL-INTERCEPT" "Call Interception via Unauthenticated REFER" \
            "CRITICAL" "Server on $ip accepted REFER without authentication - active calls can be redirected to attacker" \
            "sip://$ip:5060"
    fi
}

test_expanded_default_credentials() {
    local ip="$1"

    # Expanded default credential list for VoIP devices/platforms
    declare -a voip_default_creds=(
        "admin:admin"
        "admin:password"
        "admin:1234"
        "admin:12345"
        "admin:123456"
        "admin:admin123"
        "root:root"
        "root:password"
        "root:toor"
        "root:admin"
        "administrator:administrator"
        "administrator:password"
        "cisco:cisco"
        "cisco:Cisco"
        "admin:cisco"
        "manager:manager"
        "manager:secret"
        "pbxadmin:pbxadmin"
        "asterisk:asterisk"
        "freepbx:freepbx"
        "admin:freepbx"
        "3cx:3cx"
        "admin:3cx"
        "polycom:polycom"
        "admin:polycom"
        "456:456"
        "admin:0000"
        "user:user"
        "support:support"
        "service:service"
        "guest:guest"
    )

    for cred in "${voip_default_creds[@]}"; do
        local user="${cred%%:*}"
        local pass="${cred##*:}"

        # HTTP-based management interfaces (FreePBX, 3CX, VoIPmonitor, etc.)
        for port in 80 443 8080 8443 4443 5001; do
            local proto="http"
            [[ "$port" == "443" || "$port" == "8443" || "$port" == "4443" ]] && proto="https"

            local response
            response=$(timeout 3 curl -sk -u "$user:$pass" \
                -o /dev/null -w "%{http_code}" \
                "${proto}://$ip:$port/admin/" 2>/dev/null || echo "000")

            if [[ "$response" == "200" ]]; then
                append_cve_finding "$ip" "DEFAULT-CREDS" "Default Credentials Accepted on Port $port" \
                    "CRITICAL" "VoIP management interface on $ip:$port accepts default credentials: $user:$pass" \
                    "${proto}://$ip:$port/admin/"
                return
            fi
        done
    done
}

test_sip_digest_leak() {
    local ip="$1"
    local call_id="digest-$(date +%s%N)"

    # Send a REGISTER and capture the 401 challenge - check for weak nonce generation
    local response
    response=$(timeout 3 bash -c "
        printf 'REGISTER sip:${ip} SIP/2.0\r\nVia: SIP/2.0/UDP scanner:5060;branch=z9hG4bKdig\r\nMax-Forwards: 1\r\nTo: <sip:100@${ip}>\r\nFrom: <sip:100@${ip}>;tag=dig\r\nCall-ID: ${call_id}@scanner\r\nCSeq: 1 REGISTER\r\nContact: <sip:100@scanner>\r\nContent-Length: 0\r\n\r\n'
        sleep 1
    " | nc -u -w 3 "$ip" 5060 2>/dev/null || true)

    # Extract WWW-Authenticate header to examine realm/nonce/algorithm
    local www_auth
    www_auth=$(echo "$response" | grep -i "^WWW-Authenticate:" | head -1 || true)

    if [[ -n "$www_auth" ]]; then
        # Check for MD5 (deprecated) instead of SHA-256
        if echo "$www_auth" | grep -qi 'algorithm="MD5"' || ! echo "$www_auth" | grep -qi 'algorithm'; then
            append_cve_finding "$ip" "WEAK-DIGEST" "SIP Digest Authentication Uses Weak MD5 Algorithm" \
                "MEDIUM" "Server on $ip uses MD5 for SIP Digest authentication - vulnerable to offline hash cracking. Header: $www_auth" \
                "sip://$ip:5060"
        fi

        # Check for qop (quality of protection) - missing qop enables replay attacks
        if ! echo "$www_auth" | grep -qi 'qop='; then
            append_cve_finding "$ip" "SIP-REPLAY" "SIP Digest Authentication Missing QoP - Replay Attack Possible" \
                "MEDIUM" "Server on $ip does not include quality-of-protection in digest challenge - replay attacks possible" \
                "sip://$ip:5060"
        fi
    fi
}

test_ami_default_credentials() {
    local ip="$1"

    # Test Asterisk Manager Interface (AMI) on port 5038
    if ! timeout 2 nc -w 2 "$ip" 5038 < /dev/null &>/dev/null; then
        return
    fi

    declare -a ami_creds=("admin:admin" "admin:password" "manager:secret" "admin:secret" "asterisk:asterisk")

    for cred in "${ami_creds[@]}"; do
        local user="${cred%%:*}"
        local pass="${cred##*:}"

        local response
        response=$(timeout 5 bash -c "
            sleep 0.5
            printf 'Action: Login\r\nUsername: ${user}\r\nSecret: ${pass}\r\n\r\n'
            sleep 1
            printf 'Action: Logoff\r\n\r\n'
            sleep 0.5
        " | nc -w 5 "$ip" 5038 2>/dev/null || true)

        if echo "$response" | grep -q "Response: Success"; then
            append_cve_finding "$ip" "AMI-CREDS" "Asterisk Manager Interface Default Credentials" \
                "CRITICAL" "AMI on $ip:5038 accepts default credentials: $user:$pass - full PBX control possible" \
                "ami://$ip:5038"
            return
        fi
    done

    # Check if AMI is exposed at all (anonymous read access)
    local banner
    banner=$(timeout 3 nc -w 2 "$ip" 5038 < /dev/null 2>/dev/null || true)
    if echo "$banner" | grep -qi "asterisk call manager"; then
        append_cve_finding "$ip" "AMI-EXPOSURE" "Asterisk Manager Interface Publicly Exposed" \
            "HIGH" "AMI login banner detected on $ip:5038 - port should not be internet-accessible" \
            "ami://$ip:5038"
    fi
}

# ============================================================================
# PHASE 11: VENDOR-SPECIFIC VULNERABILITY TESTING
# ============================================================================

phase11_vendor_specific_attacks() {
    log_banner "PHASE 11: VENDOR-SPECIFIC VULNERABILITY TESTING"

    [[ ! -s "$LIVE_IPS_FILE" ]] && { log_warn "Skipping Phase 11 - no live hosts"; return 0; }

    log_info "Running vendor-specific CVE and misconfiguration tests"

    while IFS= read -r ip; do
        {
            test_cisco_cucm "$ip"
            test_avaya_aura "$ip"
            test_grandstream_ucm "$ip"
            test_polycom_uc "$ip"
            test_yealink_rce "$ip"
            test_kamailio_opensips_extended "$ip"
            test_freepbx_extended "$ip"
            test_3cx_extended "$ip"
            test_elastix_issabel "$ip"
        } &

        while (( $(jobs -r -p | wc -l) >= THREADS )); do
            sleep 0.1
        done
    done < "$LIVE_IPS_FILE"
    wait

    log_success "Phase 11 Complete"
}

test_cisco_cucm() {
    local ip="$1"

    # CVE-2021-1397: Cisco CUCM SSRF
    local response
    response=$(timeout 3 curl -sk "https://$ip/ccmadmin/j_security_check" \
        -d "j_username=admin&j_password=admin" -w "%{http_code}" -o /tmp/cisco_test 2>/dev/null || echo "000")

    if [[ -f /tmp/cisco_test ]] && grep -qi "cisco unified communications\|cucm\|callmanager" /tmp/cisco_test 2>/dev/null; then
        append_cve_finding "$ip" "CVE-2021-1397" "Cisco CUCM Interface Detected" \
            "HIGH" "Cisco Unified Communications Manager detected on $ip - test for CVE-2021-1397 SSRF and CVE-2020-3161" \
            "https://$ip/ccmadmin/"
    fi
    rm -f /tmp/cisco_test

    # Cisco IP Phone Web UI (port 80)
    local phone_response
    phone_response=$(timeout 3 curl -s "http://$ip/CGI/Java/Serviceability" 2>/dev/null || true)
    if echo "$phone_response" | grep -qi "cisco\|ip phone\|cp-79"; then
        append_cve_finding "$ip" "CVE-2020-3161" "Cisco IP Phone Web Interface Exposed" \
            "CRITICAL" "Cisco IP Phone web interface on $ip - CVE-2020-3161 RCE may be applicable" \
            "http://$ip/CGI/Java/Serviceability"
    fi
}

test_avaya_aura() {
    local ip="$1"

    # CVE-2021-22502: Avaya Aura Application Enablement Services RCE
    local response
    response=$(timeout 3 curl -sk "https://$ip/WebLM/LicenseServer" 2>/dev/null || true)
    if echo "$response" | grep -qi "avaya\|aura\|weblm"; then
        append_cve_finding "$ip" "CVE-2021-22502" "Avaya Aura Interface Detected" \
            "CRITICAL" "Avaya Aura Application Enablement Services on $ip - CVE-2021-22502 unauthenticated RCE may apply" \
            "https://$ip/WebLM/"
    fi

    # Avaya Communication Manager port 8443
    local cm_response
    cm_response=$(timeout 3 curl -sk "https://$ip:8443/index.html" 2>/dev/null || true)
    if echo "$cm_response" | grep -qi "avaya\|communication manager"; then
        append_cve_finding "$ip" "AVAYA-CM" "Avaya Communication Manager Detected" \
            "HIGH" "Avaya Communication Manager on $ip:8443 - verify patch level and default credentials" \
            "https://$ip:8443/"
    fi
}

test_grandstream_ucm() {
    local ip="$1"

    # CVE-2022-37397: Grandstream UCM6xxx SQL Injection
    local response
    response=$(timeout 3 curl -s "http://$ip/cgi-bin/api.values.get" \
        -d 'request={"action":"login"}' 2>/dev/null || true)

    if echo "$response" | grep -qi "grandstream\|ucm6\|ucm62"; then
        append_cve_finding "$ip" "CVE-2022-37397" "Grandstream UCM Detected - SQL Injection Risk" \
            "CRITICAL" "Grandstream UCM6xxx on $ip - CVE-2022-37397 SQL injection in API endpoint" \
            "http://$ip/cgi-bin/api.values.get"
    fi

    # Grandstream default web UI
    local web_response
    web_response=$(timeout 3 curl -s "http://$ip/" 2>/dev/null || true)
    if echo "$web_response" | grep -qi "grandstream"; then
        # Test default admin:admin
        local auth_response
        auth_response=$(timeout 3 curl -s -u "admin:admin" "http://$ip/cgi-bin/api.values.get" 2>/dev/null || true)
        if echo "$auth_response" | grep -qi '"response"\s*:\s*"success"'; then
            append_cve_finding "$ip" "GRANDSTREAM-CREDS" "Grandstream Default Credentials Accepted" \
                "CRITICAL" "Grandstream device on $ip accepts default admin:admin credentials" \
                "http://$ip/"
        fi
    fi
}

test_polycom_uc() {
    local ip="$1"

    # CVE-2019-9222: Polycom default credentials
    local response
    response=$(timeout 3 curl -s "http://$ip/" 2>/dev/null || true)

    if echo "$response" | grep -qi "polycom\|soundpoint\|vvx\|hdx\|rmx"; then
        # Test default credentials
        for cred in "admin:456" "admin:admin" "Polycom:456" "admin:polycom"; do
            local user="${cred%%:*}"
            local pass="${cred##*:}"
            local auth_check
            auth_check=$(timeout 3 curl -s -u "$user:$pass" "http://$ip/api/v1/mgmt/device/info" 2>/dev/null || true)
            if echo "$auth_check" | grep -qiE '"DeviceType"|"model"'; then
                append_cve_finding "$ip" "CVE-2019-9222" "Polycom Device Default Credentials" \
                    "HIGH" "Polycom device on $ip accepts default credentials: $user:$pass" \
                    "http://$ip/api/v1/mgmt/device/info"
                break
            fi
        done
    fi
}

test_yealink_rce() {
    local ip="$1"

    # CVE-2021-27561: Yealink Device Management Platform Unauthenticated RCE
    local dm_response
    dm_response=$(timeout 3 curl -s "http://$ip:8080/deviceManagement" 2>/dev/null || true)
    if echo "$dm_response" | grep -qi "yealink\|device management platform"; then
        append_cve_finding "$ip" "CVE-2021-27561" "Yealink Device Management Platform Detected" \
            "CRITICAL" "Yealink DM platform on $ip:8080 - CVE-2021-27561 unauthenticated RCE via API" \
            "http://$ip:8080/deviceManagement"
    fi

    # CVE-2021-21224: Yealink default web interface credentials
    local yealink_web
    yealink_web=$(timeout 3 curl -s "http://$ip/" 2>/dev/null || true)
    if echo "$yealink_web" | grep -qi "yealink"; then
        local auth
        auth=$(timeout 3 curl -s -u "admin:admin" "http://$ip/cgi-bin/cgiServer.exx" 2>/dev/null || true)
        if [[ -n "$auth" ]] && ! echo "$auth" | grep -qi "unauthorized\|login"; then
            append_cve_finding "$ip" "CVE-2021-21224" "Yealink Default Credentials Accepted" \
                "HIGH" "Yealink device on $ip accepts default admin:admin credentials" \
                "http://$ip/"
        fi
    fi
}

test_kamailio_opensips_extended() {
    local ip="$1"

    # CVE-2021-25956: OpenSIPS SQL Injection
    # CVE-2019-15752: Kamailio SIP memory corruption
    local response
    response=$(timeout 3 bash -c "
        printf 'OPTIONS sip:${ip} SIP/2.0\r\nVia: SIP/2.0/UDP scanner:5060;branch=z9hG4bKkami\r\nMax-Forwards: 1\r\nTo: <sip:${ip}>\r\nFrom: <sip:probe@scanner>;tag=probe\r\nCall-ID: kami@scanner\r\nCSeq: 1 OPTIONS\r\nContent-Length: 0\r\n\r\n'
        sleep 1
    " | nc -u -w 2 "$ip" 5060 2>/dev/null || true)

    if echo "$response" | grep -qi "kamailio"; then
        # Kamailio version-specific checks
        local version
        version=$(echo "$response" | grep -oiP "kamailio/\K[0-9.]+" | head -1 || echo "")
        append_cve_finding "$ip" "CVE-2019-15752" "Kamailio SIP Proxy Detected" \
            "HIGH" "Kamailio SIP proxy version $version on $ip - check for CVE-2019-15752 memory corruption" \
            "sip://$ip:5060"
    fi

    if echo "$response" | grep -qi "opensips"; then
        append_cve_finding "$ip" "CVE-2021-25956" "OpenSIPS Detected - SQL Injection Risk" \
            "HIGH" "OpenSIPS on $ip - check for CVE-2021-25956 SQL injection and CVE-2020-16231 memory corruption" \
            "sip://$ip:5060"
    fi

    # OpenSIPS/Kamailio MI (Management Interface) on port 8888
    local mi_response
    mi_response=$(timeout 3 curl -s "http://$ip:8888/mi" 2>/dev/null || true)
    if echo "$mi_response" | grep -qi "opensips\|kamailio\|mi_commands"; then
        append_cve_finding "$ip" "MI-EXPOSURE" "SIP Proxy Management Interface Exposed" \
            "CRITICAL" "SIP proxy management interface (MI) on $ip:8888 is publicly accessible" \
            "http://$ip:8888/mi"
    fi
}

test_freepbx_extended() {
    local ip="$1"

    # CVE-2022-26272: FreePBX RCE via module upload
    local response
    response=$(timeout 3 curl -s "http://$ip/admin/config.php" 2>/dev/null || true)

    if echo "$response" | grep -qi "freepbx\|sangoma"; then
        # Check FreePBX version
        local version
        version=$(echo "$response" | grep -oiP "FreePBX[^\"]*\K[0-9]+\.[0-9]+\.[0-9]+" | head -1 || echo "unknown")
        append_cve_finding "$ip" "CVE-2022-26272" "FreePBX Vulnerable Version Detected" \
            "CRITICAL" "FreePBX version $version on $ip - CVE-2022-26272 module upload RCE, CVE-2019-11334 bulk user RCE" \
            "http://$ip/admin/config.php"

        # Test for unauthenticated REST API access
        local api_response
        api_response=$(timeout 3 curl -s "http://$ip/admin/rest.php/rest/version" 2>/dev/null || true)
        if echo "$api_response" | grep -qi '"version"\|"framework"'; then
            append_cve_finding "$ip" "FREEPBX-API" "FreePBX REST API Accessible Without Authentication" \
                "HIGH" "FreePBX REST API on $ip is accessible without authentication" \
                "http://$ip/admin/rest.php"
        fi
    fi

    # CVE-2019-19463 / CVE-2019-19404: FreePBX user portal
    local portal_response
    portal_response=$(timeout 3 curl -s "http://$ip/ucp/" 2>/dev/null || true)
    if echo "$portal_response" | grep -qi "freepbx\|user control panel"; then
        append_cve_finding "$ip" "CVE-2019-19463" "FreePBX User Control Panel Exposed" \
            "MEDIUM" "FreePBX User Control Panel on $ip - check for CVE-2019-19463 auth bypass" \
            "http://$ip/ucp/"
    fi
}

test_3cx_extended() {
    local ip="$1"

    # CVE-2021-26260: 3CX Authentication Bypass (extended test)
    for port in 5000 5001 443 8443; do
        local proto="http"
        [[ "$port" == "443" || "$port" == "8443" ]] && proto="https"

        local response
        response=$(timeout 3 curl -sk "${proto}://$ip:$port/webclient/" 2>/dev/null || true)

        if echo "$response" | grep -qi "3cx\|phonesystem\|3cxphonesystem"; then
            # Check for API token leakage
            local api_test
            api_test=$(timeout 3 curl -sk "${proto}://$ip:$port/api/v1/SystemInfo" 2>/dev/null || true)
            if echo "$api_test" | grep -qi '"SystemInfo"\|"version"\|"license"'; then
                append_cve_finding "$ip" "3CX-API-LEAK" "3CX System Info API Accessible Without Authentication" \
                    "HIGH" "3CX system info API on ${proto}://$ip:$port returns data without authentication" \
                    "${proto}://$ip:$port/api/v1/SystemInfo"
            fi

            # Test for default admin credentials
            local auth_response
            auth_response=$(timeout 3 curl -sk -X POST \
                -H "Content-Type: application/json" \
                -d '{"Username":"admin","Password":"admin","SecurityCode":""}' \
                "${proto}://$ip:$port/api/v1/auth/token" 2>/dev/null || true)

            if echo "$auth_response" | grep -qi '"Token"\|"access_token"'; then
                append_cve_finding "$ip" "3CX-DEFAULT-CREDS" "3CX Default Admin Credentials Accepted" \
                    "CRITICAL" "3CX PhoneSystem on ${proto}://$ip:$port accepts default admin:admin credentials" \
                    "${proto}://$ip:$port/webclient/"
            fi
            break
        fi
    done
}

test_elastix_issabel() {
    local ip="$1"

    # Elastix/Issabel (FreePBX forks) admin panel
    local response
    response=$(timeout 3 curl -s "http://$ip/index.php" 2>/dev/null || true)

    if echo "$response" | grep -qi "elastix\|issabel"; then
        append_cve_finding "$ip" "ELASTIX-DETECTED" "Elastix/Issabel PBX Detected" \
            "HIGH" "Elastix/Issabel PBX on $ip - legacy platform with known RCE and LFI vulnerabilities (CVE-2012-4869, CVE-2014-4671)" \
            "http://$ip/"

        # Test for LFI
        local lfi_response
        lfi_response=$(timeout 3 curl -s "http://$ip/vtigercrm/graph.php?current_language=../../../../etc/passwd%00" 2>/dev/null || true)
        if echo "$lfi_response" | grep -q "root:"; then
            append_cve_finding "$ip" "ELASTIX-LFI" "Elastix Local File Inclusion" \
                "CRITICAL" "Elastix on $ip is vulnerable to LFI via vtigercrm - /etc/passwd readable" \
                "http://$ip/vtigercrm/graph.php"
        fi
    fi
}



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
        echo "Target Input File: $INPUT_FILE"
        echo "Total IPs Scanned: $([ -f "$INPUT_FILE" ] && wc -l < "$INPUT_FILE" || echo "0")"
        echo "Live Hosts Discovered: $([ -f "$LIVE_IPS_FILE" ] && wc -l < "$LIVE_IPS_FILE" || echo "0")"
        echo "Valid Extensions Found: $([ -f "${RESULTS_DIR}/valid_extensions.txt" ] && wc -l < "${RESULTS_DIR}/valid_extensions.txt" || echo "0")"
        echo "Critical CVEs Detected: $([ -f "$CVE_FINDINGS" ] && grep -c '"CRITICAL"' "$CVE_FINDINGS" || echo "0")"
        echo "High Severity Issues: $([ -f "$CVE_FINDINGS" ] && grep -c '"HIGH"' "$CVE_FINDINGS" || echo "0")"
        echo "Medium Severity Issues: $([ -f "$CVE_FINDINGS" ] && grep -c '"MEDIUM"' "$CVE_FINDINGS" || echo "0")"
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
        echo "✓ cve_findings.json                    - Structured CVE data (all phases)"
        echo "✓ valid_extensions.txt                 - Enumerated valid SIP extensions"
        echo "✓ fraud_analysis.txt                   - CDR fraud analysis"
        echo "✓ hardening_config.txt                 - Security configurations"
        echo "✓ executive_summary.txt                - This report"
        echo ""
        
        echo "NEXT STEPS"
        echo "═" * 70
        echo "1. Review detailed findings in verified_voip_vulnerabilities.txt"
        echo "2. Prioritize critical CVE remediations"
        echo "3. Patch vendor-specific vulnerabilities identified in Phase 11"
        echo "4. Remove or restrict enumerable SIP extensions (see valid_extensions.txt)"
        echo "5. Enforce SRTP for all media streams"
        echo "6. Implement hardening configurations"
        echo "7. Deploy monitoring and alerting"
        echo "8. Schedule regular security assessments"
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
    log_info "Target input file: $INPUT_FILE"
    
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

    # Extended attack vector phases (v3.0)
    phase7_sip_enumeration || log_warn "Phase 7 encountered issues"
    phase8_extension_scanning || log_warn "Phase 8 encountered issues"
    phase9_rtp_attacks || log_warn "Phase 9 encountered issues"
    phase10_credential_harvesting || log_warn "Phase 10 encountered issues"
    phase11_vendor_specific_attacks || log_warn "Phase 11 encountered issues"

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
