#!/bin/bash

###############################################################################
# VoIP IP Verification Funnel - Production-Grade Security Automation
# Three-Phase Verification Workflow for VoIP Infrastructure Reconnaissance
###############################################################################

set -euo pipefail

# Script metadata
readonly SCRIPT_VERSION="1.0.0"
readonly SCRIPT_NAME="$(basename "$0")"
readonly INPUT_FILE="${1:-shodan_ips.txt}"
readonly LOG_DIR="./logs"
readonly LOG_FILE="${LOG_DIR}/voip_verification_$(date +%Y%m%d_%H%M%S).log"
readonly TEMP_DIR=$(mktemp -d)

# Configuration parameters
readonly MASSCAN_RATE=5000
readonly VOIP_PORTS=("5060" "5061" "2000")
readonly THREADS=10
readonly NUCLEI_SEVERITY="critical,high,medium"

# Output files
readonly LIVE_IPS_FILE="${TEMP_DIR}/live_ips.txt"
readonly FINGERPRINTS_FILE="${TEMP_DIR}/fingerprints.json"
readonly VULNERABILITIES_FILE="verified_voip_vulnerabilities.txt"

###############################################################################
# LOGGING FUNCTIONS
###############################################################################

# Initialize logging
initialize_logging() {
    mkdir -p "$LOG_DIR"
    exec 1> >(tee -a "$LOG_FILE")
    exec 2>&1
    log_info "=== VoIP Verification Funnel Started ==="
    log_info "Script Version: $SCRIPT_VERSION"
    log_info "Execution Date: $(date '+%Y-%m-%d %H:%M:%S')"
    log_info "Input File: $INPUT_FILE"
    log_info "Temporary Directory: $TEMP_DIR"
}

# Log information
log_info() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [INFO] $*"
}

# Log errors
log_error() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [ERROR] $*" >&2
}

# Log warnings
log_warn() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [WARN] $*"
}

# Log debug information
log_debug() {
    [[ "${DEBUG:-0}" == "1" ]] && echo "[$(date '+%Y-%m-%d %H:%M:%S')] [DEBUG] $*" || true
}

###############################################################################
# VALIDATION FUNCTIONS
###############################################################################

# Validate input file exists and contains valid IP addresses
validate_input() {
    if [[ ! -f "$INPUT_FILE" ]]; then
        log_error "Input file not found: $INPUT_FILE"
        return 1
    fi

    if [[ ! -s "$INPUT_FILE" ]]; then
        log_error "Input file is empty: $INPUT_FILE"
        return 1
    fi

    local ip_count=0
    while IFS= read -r ip || [[ -n "$ip" ]]; do
        # Skip empty lines and comments
        [[ -z "$ip" || "$ip" =~ ^# ]] && continue
        
        # Validate IP address format (basic IPv4 check)
        if [[ $ip =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
            ((ip_count++))
        else
            log_warn "Invalid IP address format: $ip"
        fi
    done < "$INPUT_FILE"

    if [[ $ip_count -eq 0 ]]; then
        log_error "No valid IP addresses found in $INPUT_FILE"
        return 1
    fi

    log_info "Validated $ip_count IP addresses from input file"
    return 0
}

# Check if required tools are installed
validate_dependencies() {
    local missing_tools=()
    
    for tool in masscan nmap jq nuclei; do
        if ! command -v "$tool" &> /dev/null; then
            missing_tools+=("$tool")
            log_warn "Tool not found: $tool"
        fi
    done

    if [[ ${#missing_tools[@]} -gt 0 ]]; then
        log_error "Missing required tools: ${missing_tools[*]}"
        log_error "Please install: ${missing_tools[*]}"
        return 1
    fi

    log_info "All required dependencies validated"
    return 0
}

###############################################################################
# PHASE 1: DISCOVERY - MASSCAN PORT SCANNING
###############################################################################

phase1_discovery() {
    log_info "=== PHASE 1: DISCOVERY - Starting Port Scanning ==="
    
    # Create temporary masscan output file
    local masscan_output="${TEMP_DIR}/masscan_output.txt"
    
    # Build port specification
    local port_spec=$(IFS=,; echo "${VOIP_PORTS[*]}")
    log_info "Scanning ports: $port_spec at ${MASSCAN_RATE} pps"
    
    # Run masscan with appropriate verbosity
    if ! masscan -iL "$INPUT_FILE" \
        -p "$port_spec" \
        --rate="$MASSCAN_RATE" \
        --output-format list \
        --output-filename "$masscan_output" \
        2>&1 | tee -a "$LOG_FILE"; then
        log_error "Masscan execution failed"
        return 1
    fi

    # Parse masscan results and extract live IPs
    if [[ -f "$masscan_output" ]]; then
        log_debug "Masscan output file: $masscan_output"
        
        # Extract unique IPs from masscan output (format: Host:Port/Proto/State/Reason)
        awk -F' ' '{print $1}' "$masscan_output" | sort -u > "$LIVE_IPS_FILE"
        
        local live_count=$(wc -l < "$LIVE_IPS_FILE")
        log_info "Discovery complete: $live_count live hosts identified"
        
        if [[ $live_count -eq 0 ]]; then
            log_warn "No live hosts detected. Proceeding to next phase with zero targets."
            return 0
        fi
        
        log_info "Live IPs saved to: $LIVE_IPS_FILE"
        head -5 "$LIVE_IPS_FILE" >> "$LOG_FILE"
        [[ $live_count -gt 5 ]] && echo "... and $((live_count - 5)) more" >> "$LOG_FILE"
    else
        log_error "Masscan output file not created"
        return 1
    fi

    log_info "=== PHASE 1: DISCOVERY - Complete ==="
    return 0
}

###############################################################################
# PHASE 2: FINGERPRINTING - SIP BANNER GRAB
###############################################################################

# Individual SIP banner grab function (called by xargs)
perform_sip_banner_grab() {
    local ip="$1"
    local port="$2"
    
    # Send SIP OPTIONS request and capture response
    {
        timeout 5 nmap -sV -p "$port" --script=sip-enum-users "$ip" 2>/dev/null || true
    } | grep -E "Service|Product|Version|extrainfo" || true
}

export -f perform_sip_banner_grab

# Phase 2: Fingerprinting workflow
phase2_fingerprinting() {
    log_info "=== PHASE 2: FINGERPRINTING - Starting SIP Identification ==="
    
    # Check if we have live IPs to process
    if [[ ! -f "$LIVE_IPS_FILE" ]] || [[ ! -s "$LIVE_IPS_FILE" ]]; then
        log_warn "No live IPs available for fingerprinting. Skipping Phase 2."
        touch "$FINGERPRINTS_FILE"
        return 0
    fi

    local fingerprint_temp="${TEMP_DIR}/fingerprints_raw.txt"
    
    # Initialize fingerprints JSON array
    echo "[]" > "$FINGERPRINTS_FILE"
    
    log_info "Starting multithreaded SIP banner grabs (${THREADS} threads)"
    
    # Process each live IP against all VoIP ports with multithreading
    local job_count=0
    while IFS= read -r ip; do
        [[ -z "$ip" ]] && continue
        
        for port in "${VOIP_PORTS[@]}"; do
            # Submit job and track background process count
            {
                log_debug "Fingerprinting $ip:$port"
                perform_sip_banner_grab "$ip" "$port" >> "$fingerprint_temp" 2>&1
                echo "---" >> "$fingerprint_temp"
            } &
            
            # Limit concurrent processes
            ((job_count++))
            if (( job_count >= THREADS )); then
                wait -n
                ((job_count--))
            fi
        done
    done < "$LIVE_IPS_FILE"
    
    # Wait for all remaining background jobs
    wait
    
    log_info "SIP fingerprinting complete"
    [[ -f "$fingerprint_temp" ]] && log_info "Fingerprint data: $(wc -l < "$fingerprint_temp") lines"
    
    log_info "=== PHASE 2: FINGERPRINTING - Complete ==="
    return 0
}

###############################################################################
# PHASE 3: VULNERABILITY DETECTION - NUCLEI SCANNING
###############################################################################

phase3_vulnerability_detection() {
    log_info "=== PHASE 3: VULNERABILITY DETECTION - Starting Nuclei Scans ==="
    
    # Check if we have live IPs to process
    if [[ ! -f "$LIVE_IPS_FILE" ]] || [[ ! -s "$LIVE_IPS_FILE" ]]; then
        log_warn "No live IPs available for vulnerability scanning. Skipping Phase 3."
        touch "$VULNERABILITIES_FILE"
        return 0
    fi

    local nuclei_output="${TEMP_DIR}/nuclei_results.json"
    
    log_info "Running Nuclei with VoIP/SIP templates against ${THREADS} parallel targets"
    
    # Execute Nuclei with VoIP-specific templates
    if nuclei -l "$LIVE_IPS_FILE" \
        -tags voip,sip \
        -severity "$NUCLEI_SEVERITY" \
        -json \
        -o "$nuclei_output" \
        -stats \
        2>&1 | tee -a "$LOG_FILE"; then
        
        log_info "Nuclei scanning completed"
        
        # Parse and format Nuclei results
        if [[ -f "$nuclei_output" ]] && [[ -s "$nuclei_output" ]]; then
            format_vulnerability_output "$nuclei_output"
            local vuln_count=$(grep -c "^Target:" "$VULNERABILITIES_FILE" || echo "0")
            log_info "Vulnerability Detection Complete: $vuln_count findings identified"
        else
            log_warn "Nuclei produced no vulnerability findings"
            touch "$VULNERABILITIES_FILE"
        fi
    else
        log_warn "Nuclei execution completed with warnings"
        touch "$VULNERABILITIES_FILE"
    fi
    
    log_info "=== PHASE 3: VULNERABILITY DETECTION - Complete ==="
    return 0
}

# Format Nuclei JSON output into human-readable report
format_vulnerability_output() {
    local nuclei_json="$1"
    
    {
        echo "╔════════════════════════════════════════════════════════════════════╗"
        echo "║         VoIP Vulnerability Assessment Report                      ║"
        echo "║         Generated: $(date '+%Y-%m-%d %H:%M:%S')                   ║"
        echo "╚════════════════════════════════════════════════════════════════════╝"
        echo ""
        
        # Parse JSON and format findings
        jq -r '.[] | 
            "Target: \(.host)\n" +
            "Port: \(.port // "N/A")\n" +
            "Vulnerability: \(.info.name)\n" +
            "Severity: \(.info.severity)\n" +
            "Template ID: \(.template_id)\n" +
            "Description: \(.info.description // "N/A")\n" +
            "Matched At: \(.matched_at // "N/A")\n" +
            "---\n"' "$nuclei_json" 2>/dev/null || \
        echo "Note: Could not parse Nuclei JSON output. Raw output available in logs."
        
        echo ""
        echo "Report generated by: $SCRIPT_NAME (v$SCRIPT_VERSION)"
    } > "$VULNERABILITIES_FILE"
}

###############################################################################
# CLEANUP AND EXIT HANDLING
###############################################################################

# Cleanup temporary files
cleanup() {
    log_info "=== Cleanup Starting ==="
    
    if [[ -d "$TEMP_DIR" ]]; then
        log_debug "Removing temporary directory: $TEMP_DIR"
        rm -rf "$TEMP_DIR"
    fi
    
    log_info "Cleanup complete"
    log_info "Final output: $VULNERABILITIES_FILE"
    log_info "=== VoIP Verification Funnel Execution Complete ==="
}

# Error handler with cleanup
error_handler() {
    local line_number=$?
    log_error "Script failed at line $line_number"
    cleanup
    exit 1
}

# Set traps for cleanup
trap cleanup EXIT
trap error_handler ERR

###############################################################################
# MAIN EXECUTION FLOW
###############################################################################

main() {
    initialize_logging
    
    log_info "Input file: $INPUT_FILE"
    log_info "Output file: $VULNERABILITIES_FILE"
    
    # Validate prerequisites
    if ! validate_input; then
        log_error "Input validation failed"
        return 1
    fi
    
    if ! validate_dependencies; then
        log_error "Dependency validation failed"
        return 1
    fi
    
    # Execute three-phase workflow
    if ! phase1_discovery; then
        log_error "Phase 1 (Discovery) failed"
        return 1
    fi
    
    if ! phase2_fingerprinting; then
        log_error "Phase 2 (Fingerprinting) failed"
        return 1
    fi
    
    if ! phase3_vulnerability_detection; then
        log_error "Phase 3 (Vulnerability Detection) failed"
        return 1
    fi
    
    log_info "All phases completed successfully"
    
    # Display final results
    if [[ -f "$VULNERABILITIES_FILE" ]]; then
        log_info "=== Vulnerability Report Summary ==="
        head -20 "$VULNERABILITIES_FILE"
    fi
    
    return 0
}

# Execute main function
main "$@"
exit $?
