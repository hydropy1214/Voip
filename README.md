# VoIP Security Assessment Framework

**Professional-grade VoIP vulnerability detection and security testing platform**

## Overview

This framework provides comprehensive, modular security testing for VoIP infrastructure including:

- **25+ CVE Detections** across major VoIP platforms (Asterisk, FreePBX, 3CX, Cisco, Grandstream, FreeSWITCH, etc.)
- **SIP Protocol Analysis** with exploitation capabilities
- **RTP/SRTP Security** validation and media stream analysis
- **Credential Enumeration** and brute-force testing (authorized)
- **DoS/DDoS Resilience** assessment
- **Call Hijacking Detection**
- **Toll-Fraud Prevention** modeling and detection
- **Compliance Auditing** (HIPAA, PCI-DSS, SOX)

## Features

### Phase 1: Core Detection
- ✅ CVE vulnerability scanning (25+ known exploits)
- ✅ Default credential testing
- ✅ Weak cipher detection
- ✅ Service fingerprinting

### Phase 2: Protocol Analysis
- ✅ SIP OPTIONS reconnaissance
- ✅ REGISTER/INVITE manipulation
- ✅ RTP stream detection and analysis
- ✅ SRTP encryption validation
- ✅ TLS/SSL cipher analysis

### Phase 3: Advanced Testing
- ✅ Toll-fraud simulation
- ✅ Call routing analysis
- ✅ Privilege escalation paths
- ✅ Configuration audit
- ✅ Backup/recovery verification

### Phase 4: Reporting & Integration
- ✅ Machine-readable reports (JSON, XML)
- ✅ Risk scoring (CVSS)
- ✅ Remediation templates
- ✅ SIEM integration hooks
- ✅ Compliance mapping

## Installation

```bash
git clone https://github.com/hydropy1214/Voip.git
cd Voip
pip install -r requirements.txt
./setup.sh --install
```

## Quick Start

```bash
# Basic scan
sudo python3 voip_scanner.py --target 192.168.1.100 --profile comprehensive

# Authorized testing (requires confirmation)
sudo python3 voip_scanner.py --target 192.168.1.100 --authorized --profile aggressive

# Generate compliance report
python3 voip_scanner.py --target 192.168.1.100 --report hipaa --output report.pdf
```

## Directory Structure

```
Voip/
├── README.md
├── requirements.txt
├── setup.sh
├── voip_scanner.py          # Main entry point
├── config/
│   ├── cve_definitions.json # CVE detection rules
│   ├── profiles.yaml        # Scan profiles
│   └── compliance.yaml      # Compliance frameworks
├── modules/
│   ├── __init__.py
│   ├── core/
│   │   ├── sip_protocol.py  # SIP handling
│   │   ├── rtp_analysis.py  # RTP/SRTP analysis
│   │   └── auth.py          # Authorization checks
│   ├── exploits/
│   │   ├── cve_registry.py  # CVE definitions
│   │   ├── asterisk.py      # Asterisk-specific
│   │   ├── freepbx.py       # FreePBX-specific
│   │   ├── 3cx.py           # 3CX-specific
│   │   └── cisco.py         # Cisco-specific
│   ├── detection/
│   │   ├── fingerprint.py   # Service identification
│   │   ├── credentials.py   # Credential testing
│   │   └── dosresilience.py # DoS testing
│   ├── analysis/
│   │   ├── toll_fraud.py    # Toll-fraud detection
│   │   ├── call_hijack.py   # Call hijacking analysis
│   │   └── compliance.py    # Compliance checking
│   └── reporting/
│       ├── formatter.py     # Report formatting
│       ├── export.py        # Export handlers
│       └── siem_hooks.py    # SIEM integration
├── tests/
│   ├── unit/
│   ├── integration/
│   └── fixtures/
├── templates/
│   ├── remediation/
│   └── reports/
└── docker/
    ├── Dockerfile
    └── docker-compose.yml
```

## Compliance & Legal

⚠️ **Authorization Required**: This tool is designed for authorized security testing only.

- Obtain written permission before testing
- Comply with applicable laws (CFAA, GDPR, local regulations)
- Document authorization and scope
- Do not disrupt production systems
- Report findings responsibly

## Documentation

See `/docs/` for detailed guides:
- [CVE Detections](docs/CVE_DETECTIONS.md)
- [Exploitation Guide](docs/EXPLOITATION.md)
- [Remediation Templates](docs/REMEDIATION.md)
- [Compliance Mapping](docs/COMPLIANCE.md)

## Contributing

Contributions welcome! See [CONTRIBUTING.md](CONTRIBUTING.md)

## License

MIT License - See [LICENSE](LICENSE)
