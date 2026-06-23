# VoIP CVE Detection Guide

## Critical Vulnerabilities

### CVE-2021-30461: VoIPmonitor RCE
- **Platform**: VoIPmonitor
- **Severity**: CRITICAL (CVSS 9.8)
- **Description**: Unauthenticated remote code execution via web interface
- **Detection**: HTTP POST to `/index.php` with test credentials
- **Fix**: Update to version 5.4+
- **Risk**: Complete system compromise

### CVE-2019-11334: FreePBX Backup RCE
- **Platform**: FreePBX
- **Severity**: CRITICAL (CVSS 9.8)
- **Description**: RCE in backup module without authentication
- **Detection**: Access `/admin/modules/core/functions.inc.php`
- **Fix**: Update to FreePBX 15.0.22+
- **Risk**: Complete system compromise

### CVE-2023-27581: Grandstream Command Injection
- **Platform**: Grandstream UCM
- **Severity**: CRITICAL (CVSS 9.8)
- **Description**: Command execution via `/cgi-bin/execute` endpoint
- **Detection**: POST request with `cmd=id` payload
- **Fix**: Update Grandstream firmware
- **Risk**: Complete system compromise

### CVE-2022-29535: FreeSWITCH Default Password
- **Platform**: FreeSWITCH
- **Severity**: CRITICAL (CVSS 9.8)
- **Description**: Event socket accepts default password "ClueCon"
- **Detection**: Connect to port 8021 and send `auth ClueCon`
- **Fix**: Change password in `event_socket.conf.xml`
- **Risk**: Complete system compromise

## High Severity Vulnerabilities

### CVE-2022-24260: Cisco IP Phone DoS
- **Platform**: Cisco IP Phones (8800, 8900 series)
- **Severity**: HIGH (CVSS 7.5)
- **Description**: Denial of service via malformed SIP packets
- **Detection**: Send malformed SIP INVITE with oversized Via header
- **Fix**: Update phone firmware
- **Risk**: Service interruption

### CVE-2020-14144: Asterisk Remote Crash
- **Platform**: Asterisk
- **Severity**: HIGH (CVSS 7.5)
- **Description**: Remote crash via malformed REGISTER with CSeq overflow
- **Detection**: Send REGISTER with CSeq: 2147483648
- **Fix**: Update Asterisk to 13.36+, 14.10+, 15.10+, 16.8+
- **Risk**: Service interruption

## Medium Severity Vulnerabilities

### CVE-2020-12701: Asterisk Weak TLS
- **Platform**: Asterisk
- **Severity**: MEDIUM (CVSS 5.9)
- **Description**: Support for weak/export-grade TLS ciphers
- **Detection**: TLS connection with EXPORT ciphers
- **Fix**: Disable weak ciphers in asterisk.conf
- **Risk**: Man-in-the-middle attacks possible

## Detection Methods

### HTTP-Based
- Check for web interfaces on ports 80, 443, 8080, 8443
- Send credentials test (admin/admin, admin/password)
- Check for known vulnerable endpoints

### SIP-Based  
- Send SIP OPTIONS for fingerprinting
- Test REGISTER with various credentials
- Send malformed packets to test resilience
- Check SIP server banners

### Socket-Based
- Test event sockets (FreeSWITCH port 8021)
- Test SSH (port 22)
- Test Telnet (port 23)

### TLS-Based
- Check certificate validity
- Test supported TLS versions
- Analyze cipher suites
- Check for weak encryption

## Assessment Workflow

```
1. Fingerprinting
   └─> Identify platform and version
   └─> Detect enabled services
   └─> Collect banners

2. CVE Detection
   └─> Check critical CVEs
   └─> Check platform-specific CVEs
   └─> Verify vulnerability presence

3. Credential Testing
   └─> Test default credentials
   └─> Enumerate extensions
   └─> Test weak passwords

4. Security Analysis
   └─> Analyze encryption (RTP/SRTP)
   └─> Test TLS/SSL configuration
   └─> Check authentication methods

5. Resilience Testing
   └─> SIP flood test
   └─> Malformed packet test
   └─> Slowloris test
   └─> UDP flooding test

6. Compliance Check
   └─> HIPAA requirements
   └─> PCI-DSS requirements
   └─> SOX requirements
   └─> GDPR requirements

7. Reporting
   └─> Generate risk score
   └─> Provide remediation steps
   └─> Estimate financial impact
```

## Testing Safely

### Non-Destructive Testing
- Use read-only operations only
- Avoid exploiting vulnerabilities
- Don't modify configurations
- Don't disrupt service
- Document all activities

### Dos Test Caution
- Minimal packet count (100 packets max)
- Monitor service responsiveness
- Have rollback ready
- Test during maintenance window
- Have kill switch prepared
