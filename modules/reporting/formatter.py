#!/usr/bin/env python3
"""
Report Formatter
Formats vulnerability assessment results for various output formats
"""

import json
import logging
from typing import Dict, Any
from datetime import datetime
from enum import Enum

logger = logging.getLogger(__name__)

class RiskLevel(Enum):
    """Risk severity levels"""
    CRITICAL = 9.5
    HIGH = 7.5
    MEDIUM = 5.0
    LOW = 2.5
    INFO = 0.5

class ReportFormatter:
    """Formats assessment reports"""
    
    def __init__(self, target: str, scan_profile: str = 'standard'):
        self.target = target
        self.scan_profile = scan_profile
        self.timestamp = datetime.now().isoformat()
    
    def calculate_risk_score(self, results: Dict) -> float:
        """Calculate overall risk score (0-100)"""
        score = 0.0
        weights = {
            'critical_vulnerabilities': 25,
            'weak_credentials': 20,
            'dos_vulnerable': 15,
            'unencrypted_media': 15,
            'weak_tls': 10,
            'toll_fraud_risk': 10,
            'default_settings': 5
        }
        
        # Count vulnerabilities by severity
        critical_count = len([v for v in results.get('vulnerabilities', []) 
                             if v.get('severity') == 'CRITICAL'])
        high_count = len([v for v in results.get('vulnerabilities', []) 
                         if v.get('severity') == 'HIGH'])
        
        score += min(critical_count * 10, 25)  # Critical vulns
        score += min(high_count * 5, 10)  # High vulns
        
        if results.get('weak_credentials'):
            score += weights['weak_credentials']
        
        if results.get('dos_results', {}).get('vulnerable'):
            score += weights['dos_vulnerable']
        
        if results.get('rtp_analysis', {}).get('unencrypted'):
            score += weights['unencrypted_media']
        
        return min(score, 100.0)
    
    def generate_json_report(self, results: Dict) -> str:
        """Generate JSON formatted report"""
        logger.info("Generating JSON report")
        
        report = {
            'metadata': {
                'timestamp': self.timestamp,
                'target': self.target,
                'scan_profile': self.scan_profile,
                'framework_version': '1.0.0'
            },
            'executive_summary': {
                'overall_risk_score': self.calculate_risk_score(results),
                'risk_level': self._get_risk_level(self.calculate_risk_score(results)),
                'vulnerabilities_found': len(results.get('vulnerabilities', [])),
                'critical_count': len([v for v in results.get('vulnerabilities', []) 
                                      if v.get('severity') == 'CRITICAL']),
                'high_count': len([v for v in results.get('vulnerabilities', []) 
                                  if v.get('severity') == 'HIGH']),
                'weak_credentials_found': bool(results.get('weak_credentials')),
                'dos_resilient': not results.get('dos_results', {}).get('vulnerable', True)
            },
            'detailed_findings': results,
            'remediation': self._generate_remediation(results)
        }
        
        return json.dumps(report, indent=2, default=str)
    
    def generate_html_report(self, results: Dict) -> str:
        """Generate HTML formatted report"""
        logger.info("Generating HTML report")
        
        risk_score = self.calculate_risk_score(results)
        risk_level = self._get_risk_level(risk_score)
        
        html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>VoIP Security Assessment Report</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                .header {{ background-color: #2c3e50; color: white; padding: 20px; border-radius: 5px; }}
                .summary {{ background-color: #ecf0f1; padding: 15px; margin: 20px 0; border-left: 4px solid #3498db; }}
                .critical {{ background-color: #e74c3c; color: white; }}
                .high {{ background-color: #e67e22; color: white; }}
                .medium {{ background-color: #f39c12; color: white; }}
                .low {{ background-color: #27ae60; color: white; }}
                table {{ border-collapse: collapse; width: 100%; margin: 20px 0; }}
                th, td {{ border: 1px solid #bdc3c7; padding: 10px; text-align: left; }}
                th {{ background-color: #34495e; color: white; }}
                .vulnerable {{ background-color: #ffe6e6; }}
                .safe {{ background-color: #e6ffe6; }}
            </style>
        </head>
        <body>
            <div class="header">
                <h1>VoIP Security Assessment Report</h1>
                <p>Target: {self.target}</p>
                <p>Date: {self.timestamp}</p>
                <p>Profile: {self.scan_profile}</p>
            </div>
            
            <div class="summary">
                <h2>Executive Summary</h2>
                <p><strong>Overall Risk Score:</strong> {risk_score:.1f}/100</p>
                <p><strong>Risk Level:</strong> <span class="{risk_level.lower()}">{risk_level}</span></p>
                <p><strong>Vulnerabilities Found:</strong> {len(results.get('vulnerabilities', []))}</p>
            </div>
            
            <h2>Vulnerabilities</h2>
            <table>
                <tr>
                    <th>CVE</th>
                    <th>Title</th>
                    <th>Severity</th>
                    <th>Status</th>
                </tr>
        """
        
        for vuln in results.get('vulnerabilities', []):
            severity_class = vuln.get('severity', 'LOW').lower()
            html += f"""
                <tr>
                    <td>{vuln.get('cve_id', 'N/A')}</td>
                    <td>{vuln.get('title', 'Unknown')}</td>
                    <td><span class="{severity_class}">{vuln.get('severity', 'Unknown')}</span></td>
                    <td class="{'vulnerable' if vuln.get('vulnerable') else 'safe'}">
                        {'VULNERABLE' if vuln.get('vulnerable') else 'SAFE'}
                    </td>
                </tr>
            """
        
        html += """
            </table>
            
            <h2>Recommendations</h2>
            <ul>
        """
        
        for rec in self._generate_remediation(results).get('recommendations', []):
            html += f"<li>{rec}</li>"
        
        html += """
            </ul>
        </body>
        </html>
        """
        
        return html
    
    def generate_csv_report(self, results: Dict) -> str:
        """Generate CSV formatted report"""
        logger.info("Generating CSV report")
        
        csv_lines = [
            "CVE,Title,Severity,Status,Description"
        ]
        
        for vuln in results.get('vulnerabilities', []):
            csv_lines.append(
                f"""{vuln.get('cve_id', 'N/A')},
{vuln.get('title', 'Unknown')},
{vuln.get('severity', 'Unknown')},
{vuln.get('vulnerable', False)},
{vuln.get('description', '')}"""
            )
        
        return "\n".join(csv_lines)
    
    def _get_risk_level(self, score: float) -> str:
        """Convert score to risk level"""
        if score >= 80:
            return 'CRITICAL'
        elif score >= 60:
            return 'HIGH'
        elif score >= 40:
            return 'MEDIUM'
        elif score >= 20:
            return 'LOW'
        else:
            return 'INFO'
    
    def _generate_remediation(self, results: Dict) -> Dict:
        """Generate remediation recommendations"""
        recommendations = []
        
        # Check for critical vulnerabilities
        critical_cves = [v for v in results.get('vulnerabilities', []) 
                        if v.get('severity') == 'CRITICAL']
        if critical_cves:
            recommendations.append(f"Immediately patch {len(critical_cves)} critical vulnerabilities")
        
        # Check for weak credentials
        if results.get('weak_credentials'):
            recommendations.append("Force password reset for all users")
            recommendations.append("Implement strong password policy")
        
        # Check for DoS vulnerability
        if results.get('dos_results', {}).get('vulnerable'):
            recommendations.append("Implement rate limiting")
            recommendations.append("Deploy DDoS mitigation")
        
        # Check for unencrypted media
        if results.get('rtp_analysis', {}).get('unencrypted'):
            recommendations.append("Enable SRTP for media encryption")
        
        # Check for weak TLS
        if results.get('tls_analysis', {}).get('weak_ciphers'):
            recommendations.append("Disable weak TLS ciphers")
            recommendations.append("Update to TLS 1.2 or higher")
        
        # Check for toll fraud risk
        if results.get('toll_fraud', {}).get('high_risk'):
            recommendations.append("Block access to premium numbers")
            recommendations.append("Implement call restrictions")
        
        return {
            'total_recommendations': len(recommendations),
            'recommendations': recommendations,
            'priority': 'IMMEDIATE' if any('Immediately' in r for r in recommendations) else 'HIGH'
        }

class SIEMIntegration:
    """Integrates with SIEM systems"""
    
    def export_to_siem(self, results: Dict, siem_type: str = 'syslog') -> str:
        """Export results to SIEM format"""
        logger.info(f"Exporting to {siem_type} SIEM format")
        
        if siem_type == 'syslog':
            return self._format_syslog(results)
        elif siem_type == 'siem_json':
            return self._format_siem_json(results)
        else:
            return json.dumps(results, indent=2, default=str)
    
    def _format_syslog(self, results: Dict) -> str:
        """Format as syslog messages"""
        messages = []
        
        for vuln in results.get('vulnerabilities', []):
            severity_map = {'CRITICAL': '1', 'HIGH': '2', 'MEDIUM': '3', 'LOW': '4'}
            severity_code = severity_map.get(vuln.get('severity', 'INFO'), '5')
            
            message = (
                f"<{severity_code}> VoIP_Scanner: "
                f"CVE={vuln.get('cve_id', 'N/A')} "
                f"Title={vuln.get('title', 'Unknown')} "
                f"Status={vuln.get('vulnerable', False)}"
            )
            messages.append(message)
        
        return "\n".join(messages)
    
    def _format_siem_json(self, results: Dict) -> str:
        """Format as SIEM JSON"""
        siem_events = []
        
        for vuln in results.get('vulnerabilities', []):
            event = {
                'event_type': 'security_finding',
                'source': 'voip_scanner',
                'severity': vuln.get('severity', 'UNKNOWN'),
                'cve_id': vuln.get('cve_id', 'N/A'),
                'title': vuln.get('title', 'Unknown'),
                'timestamp': datetime.now().isoformat(),
                'status': 'VULNERABLE' if vuln.get('vulnerable') else 'SAFE'
            }
            siem_events.append(event)
        
        return json.dumps(siem_events, indent=2)
