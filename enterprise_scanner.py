#!/usr/bin/env python3
"""
Enhanced Main Scanner with Enterprise Features
Full CLI with all advanced capabilities
"""

import argparse
import sys
import json
import logging
from pathlib import Path
from datetime import datetime
from modules.enterprise_scanner import EnterpriseVoIPScanner

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('logs/voip_scanner.log')
    ]
)
logger = logging.getLogger(__name__)

__version__ = "2.0.0-ENTERPRISE"

def check_authorization():
    """
    Verify user has authorization to perform security testing
    """
    print("""
    ╔════════════════════════════════════════════════════════════════════╗
    ║        VoIP Security Assessment Framework - Enterprise Edition      ║
    ║                                                                    ║
    ║             AUTHORIZED SECURITY TESTING ONLY                      ║
    ╚════════════════════════════════════════════════════════════════════╝
    
    ⚠️  LEGAL DISCLAIMER:
    
    This tool is designed for AUTHORIZED security testing ONLY.
    
    By using this tool, you confirm:
    ✓ Written authorization from system owner
    ✓ Non-destructive testing commitment
    ✓ Legal compliance (CFAA, GDPR, local laws)
    ✓ Responsible disclosure
    
    Unauthorized access is ILLEGAL and may result in:
    ✗ Criminal prosecution
    ✗ Civil liability
    ✗ Imprisonment & fines
    
    """)
    
    response = input("Do you have written authorization? (type 'yes' to confirm): ").strip()
    if response.lower() != 'yes':
        logger.error("Authorization denied. Exiting.")
        sys.exit(1)
    
    print("✓ Authorization confirmed. Proceeding...\n")

def parse_arguments():
    """
    Parse command-line arguments
    """
    parser = argparse.ArgumentParser(
        description="VoIP Security Assessment Framework - Enterprise Edition v" + __version__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
EXAMPLES:
  # Enterprise scan (50+ CVEs, parallel processing)
  sudo python3 enterprise_scanner.py --target 192.168.1.100 --profile enterprise
  
  # Fast USA-focused assessment
  sudo python3 enterprise_scanner.py --target 192.168.1.100 --profile usa-focused
  
  # Generate compliance report
  python3 enterprise_scanner.py --target 192.168.1.100 --report hipaa --output report.json
  
  # High-performance parallel scan (100 workers)
  sudo python3 enterprise_scanner.py --target 192.168.1.100 --workers 100
        """
    )
    
    # Core arguments
    parser.add_argument('--target', '-t', required=True,
                        help='Target VoIP system IP address or hostname')
    parser.add_argument('--port', '-p', type=int, default=5060,
                        help='SIP port (default: 5060)')
    parser.add_argument('--version', action='version',
                        version=f'%(prog)s {__version__}')
    
    # Performance
    parser.add_argument('--workers', '-w', type=int, default=50,
                        help='Number of parallel workers (default: 50)')
    parser.add_argument('--timeout', type=int, default=30,
                        help='Test timeout in seconds (default: 30)')
    
    # Scan profile
    parser.add_argument('--profile', choices=['quick', 'standard', 'comprehensive', 
                                              'enterprise', 'usa-focused', 'aggressive'],
                        default='enterprise',
                        help='Scan profile (default: enterprise)')
    
    # Authorization
    parser.add_argument('--authorized', action='store_true',
                        help='Skip authorization check (pre-confirmed)')
    
    # Output options
    parser.add_argument('--output', '-o', default=None,
                        help='Output report file')
    parser.add_argument('--format', '-f', choices=['json', 'xml', 'pdf', 'html', 'csv'],
                        default='json',
                        help='Report format (default: json)')
    parser.add_argument('--report', choices=['summary', 'detailed', 'hipaa', 'pci', 'sox'],
                        default='detailed',
                        help='Report type (default: detailed)')
    
    # Testing options
    parser.add_argument('--cves-only', action='store_true',
                        help='Run CVE scanning only')
    parser.add_argument('--skip-dos', action='store_true',
                        help='Skip DoS resilience testing')
    parser.add_argument('--skip-rtp', action='store_true',
                        help='Skip RTP analysis')
    
    # Callbacks
    parser.add_argument('--callback', '-c', default=None,
                        help='Callback IP for out-of-band testing')
    parser.add_argument('--listener-port', type=int, default=9999,
                        help='Listener port (default: 9999)')
    
    # Verbosity
    parser.add_argument('--verbose', '-v', action='count', default=0,
                        help='Increase verbosity')
    parser.add_argument('--quiet', '-q', action='store_true',
                        help='Suppress output')
    
    return parser.parse_args()

def main():
    """
    Main entry point
    """
    args = parse_arguments()
    
    # Set logging level
    if args.quiet:
        logging.getLogger().setLevel(logging.CRITICAL)
    elif args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    logger.info(f"VoIP Security Assessment Framework v{__version__}")
    
    # Check authorization
    if not args.authorized:
        check_authorization()
    else:
        logger.info("✓ Authorization pre-confirmed")
    
    # Create output directory
    Path('logs').mkdir(exist_ok=True)
    Path('reports').mkdir(exist_ok=True)
    
    # Initialize enterprise scanner
    scanner = EnterpriseVoIPScanner(
        target_host=args.target,
        target_port=args.port,
        max_workers=args.workers,
        profile=args.profile
    )
    
    # Run enterprise scan
    try:
        results = scanner.run_enterprise_scan()
        
        # Generate report
        report = scanner.generate_enterprise_report(format_type=args.format)
        
        # Output report
        if args.output:
            output_path = Path(args.output)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            
            with open(output_path, 'w') as f:
                f.write(report)
            logger.info(f"Report saved to {output_path}")
        else:
            print(report)
        
        # Export to SIEM if requested
        if hasattr(args, 'export_siem') and args.export_siem:
            siem_export = scanner.export_siem_enterprise()
            logger.info("SIEM export prepared")
        
        logger.info("Assessment complete")
    
    except KeyboardInterrupt:
        logger.warning("Interrupted by user")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Fatal error: {e}", exc_info=True)
        sys.exit(1)

if __name__ == '__main__':
    main()
