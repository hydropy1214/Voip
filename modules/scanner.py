#!/usr/bin/env python3
"""
Integrated VoIP Security Scanner
Coordinates all scanning modules for comprehensive assessment
"""

import logging
from typing import Dict, List
from modules.detection.fingerprint import VoIPFingerprinter
from modules.detection.credentials import CredentialTester
from modules.detection.dos_resilience import DOSResilienceTester
from modules.analysis.rtp_security import RTPSecurityAnalyzer
from modules.analysis.tls_analysis import TLSAnalyzer
from modules.analysis.toll_fraud import TollFraudAnalyzer
from modules.exploits.cve_registry import CVERegistry, Platform
from modules.exploits.platform_exploits import (
    AsteriskExploit, FreePBXExploit, ThreeCXExploit,
    GrandstreamExploit, CiscoExploit, FreeSWITCHExploit,
    VoIPmonitorExploit
)
from modules.reporting.formatter import ReportFormatter, SIEMIntegration

logger = logging.getLogger(__name__)

class VoIPSecurityScanner:
    """Integrated VoIP security assessment scanner"""
    
    # Platform detection mapping
    PLATFORM_MAPPING = {
        'Asterisk': (Platform.ASTERISK, AsteriskExploit),
        'FreePBX': (Platform.FREEPBX, FreePBXExploit),
        '3CX': (Platform.THREE_CX, ThreeCXExploit),
        'Cisco': (Platform.CISCO, CiscoExploit),
        'Grandstream': (Platform.GRANDSTREAM, GrandstreamExploit),
        'FreeSWITCH': (Platform.FREESWITCH, FreeSWITCHExploit),
        'VoIPmonitor': (Platform.GENERIC, VoIPmonitorExploit),
    }
    
    def __init__(self, target_host: str, target_port: int = 5060, profile: str = 'standard'):
        self.target_host = target_host
        self.target_port = target_port
        self.profile = profile
        self.results = {}
        self.cve_registry = CVERegistry()
        logger.info(f"Initialized scanner for {target_host}:{target_port} (profile: {profile})")
    
    def scan_fingerprint(self) -> Dict:
        """Scan 1: Fingerprinting"""
        logger.info("Starting fingerprinting scan")
        
        try:
            fingerprinter = VoIPFingerprinter(self.target_host, self.target_port)
            result = fingerprinter.full_fingerprint()
            fingerprinter.close()
            return result
        except Exception as e:
            logger.error(f"Fingerprinting error: {e}")
            return {'error': str(e)}
    
    def scan_cves(self, platform: Platform = None) -> List[Dict]:
        """Scan 2: CVE Detection"""
        logger.info("Starting CVE scanning")
        
        vulnerabilities = []
        
        # Get CVEs for platform or all
        if platform:
            cves = self.cve_registry.get_by_platform(platform)
        else:
            cves = self.cve_registry.cves
        
        for cve in cves:
            logger.debug(f"Testing {cve.cve_id}")
            
            # Find and run exploit if available
            for platform_name, (platform_enum, exploit_class) in self.PLATFORM_MAPPING.items():
                if platform_enum == platform or not platform:
                    try:
                        exploit = exploit_class(self.target_host)
                        
                        if hasattr(exploit, f'test_{cve.cve_id.lower().replace("-", "_")}'):
                            test_method = getattr(exploit, f'test_{cve.cve_id.lower().replace("-", "_")}')
                            result = test_method()
                            
                            vulnerabilities.append({
                                'cve_id': cve.cve_id,
                                'title': cve.title,
                                'severity': cve.severity.name,
                                'cvss_score': cve.cvss_score,
                                'vulnerable': result.get('vulnerable', False),
                                'details': result
                            })
                    except Exception as e:
                        logger.debug(f"CVE test error for {cve.cve_id}: {e}")
        
        return vulnerabilities
    
    def scan_credentials(self) -> Dict:
        """Scan 3: Credential Testing"""
        logger.info("Starting credential scanning")
        
        try:
            tester = CredentialTester(self.target_host, self.target_port)
            result = tester.comprehensive_credential_test()
            tester.close()
            return result
        except Exception as e:
            logger.error(f"Credential testing error: {e}")
            return {'error': str(e)}
    
    def scan_dos_resilience(self) -> Dict:
        """Scan 4: DoS Resilience"""
        logger.info("Starting DoS resilience scanning")
        
        try:
            tester = DOSResilienceTester(self.target_host, self.target_port)
            result = tester.comprehensive_dos_test()
            tester.close()
            return result
        except Exception as e:
            logger.error(f"DoS testing error: {e}")
            return {'error': str(e)}
    
    def scan_rtp_security(self) -> Dict:
        """Scan 5: RTP/SRTP Security"""
        logger.info("Starting RTP/SRTP security scanning")
        
        try:
            analyzer = RTPSecurityAnalyzer(self.target_host)
            result = analyzer.comprehensive_rtp_analysis(duration=30)
            return result
        except Exception as e:
            logger.error(f"RTP analysis error: {e}")
            return {'error': str(e)}
    
    def scan_tls_security(self) -> Dict:
        """Scan 6: TLS/SSL Security"""
        logger.info("Starting TLS/SSL security scanning")
        
        try:
            analyzer = TLSAnalyzer(self.target_host)
            result = analyzer.comprehensive_tls_analysis()
            return result
        except Exception as e:
            logger.error(f"TLS analysis error: {e}")
            return {'error': str(e)}
    
    def scan_toll_fraud_risk(self) -> Dict:
        """Scan 7: Toll Fraud Risk Assessment"""
        logger.info("Starting toll fraud risk assessment")
        
        try:
            analyzer = TollFraudAnalyzer()
            
            # Get extensions from previous scans
            extensions = []
            weak_creds = []
            
            if 'fingerprinting' in self.results:
                extensions = [e['extension'] for e in 
                            self.results['fingerprinting'].get('extensions', {}).get('found', [])]
            
            if 'credentials' in self.results:
                weak_creds = self.results['credentials'].get('sip_registrations', [])
            
            result = analyzer.comprehensive_fraud_assessment(extensions, weak_creds)
            return result
        except Exception as e:
            logger.error(f"Toll fraud assessment error: {e}")
            return {'error': str(e)}
    
    def run_full_assessment(self) -> Dict:
        """Run complete security assessment"""
        logger.info("Starting full VoIP security assessment")
        
        # Step 1: Fingerprinting
        fingerprinting_result = self.scan_fingerprint()
        self.results['fingerprinting'] = fingerprinting_result
        
        if fingerprinting_result.get('error'):
            logger.error("Fingerprinting failed, cannot continue")
            return self.results
        
        # Determine platform for targeted testing
        platform = None
        if fingerprinting_result.get('platform', {}).get('platform'):
            for platform_name, (platform_enum, _) in self.PLATFORM_MAPPING.items():
                if platform_name.lower() in fingerprinting_result['platform']['platform'].lower():
                    platform = platform_enum
                    break
        
        # Step 2: CVE Detection
        logger.info("Scanning for CVEs...")
        self.results['vulnerabilities'] = self.scan_cves(platform)
        
        # Step 3: Credential Testing
        if self.profile in ['standard', 'comprehensive', 'aggressive']:
            logger.info("Testing credentials...")
            self.results['credentials'] = self.scan_credentials()
        
        # Step 4: DoS Resilience (only for comprehensive and aggressive)
        if self.profile in ['comprehensive', 'aggressive']:
            logger.info("Testing DoS resilience...")
            self.results['dos_resilience'] = self.scan_dos_resilience()
        
        # Step 5: RTP/SRTP Security
        if self.profile in ['comprehensive', 'aggressive']:
            logger.info("Analyzing RTP security...")
            self.results['rtp_analysis'] = self.scan_rtp_security()
        
        # Step 6: TLS/SSL Security
        if self.profile in ['standard', 'comprehensive', 'aggressive']:
            logger.info("Analyzing TLS security...")
            self.results['tls_analysis'] = self.scan_tls_security()
        
        # Step 7: Toll Fraud Risk
        if self.profile in ['comprehensive', 'aggressive']:
            logger.info("Assessing toll fraud risk...")
            self.results['toll_fraud_risk'] = self.scan_toll_fraud_risk()
        
        logger.info("Full assessment complete")
        return self.results
    
    def generate_report(self, format_type: str = 'json') -> str:
        """Generate report in specified format"""
        logger.info(f"Generating {format_type} report")
        
        formatter = ReportFormatter(self.target_host, self.profile)
        
        if format_type == 'json':
            return formatter.generate_json_report(self.results)
        elif format_type == 'html':
            return formatter.generate_html_report(self.results)
        elif format_type == 'csv':
            return formatter.generate_csv_report(self.results)
        else:
            return str(self.results)
    
    def export_to_siem(self, siem_type: str = 'syslog') -> str:
        """Export results to SIEM format"""
        logger.info(f"Exporting to {siem_type} SIEM format")
        
        siem = SIEMIntegration()
        return siem.export_to_siem(self.results, siem_type)
