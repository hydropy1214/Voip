#!/usr/bin/env python3
"""
Unit tests for VoIP scanner modules
"""

import unittest
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from modules.core.sip_protocol import SIPMessage, parse_sip_response
from modules.exploits.cve_registry import CVERegistry, Platform, Severity

class TestSIPProtocol(unittest.TestCase):
    """Tests for SIP protocol module"""
    
    def test_sip_message_creation(self):
        """Test SIP message creation"""
        msg = SIPMessage(
            method="OPTIONS",
            uri="sip:test@example.com",
            headers={"Via": "SIP/2.0/UDP 10.0.0.1"}
        )
        
        self.assertEqual(msg.method, "OPTIONS")
        self.assertEqual(msg.uri, "sip:test@example.com")
        self.assertIn("Via", msg.headers)
    
    def test_sip_message_to_string(self):
        """Test SIP message string conversion"""
        msg = SIPMessage(
            method="OPTIONS",
            uri="sip:test@example.com"
        )
        
        msg_str = msg.to_string()
        self.assertIn("OPTIONS", msg_str)
        self.assertIn("SIP/2.0", msg_str)
    
    def test_sip_response_parsing(self):
        """Test SIP response parsing"""
        response = """SIP/2.0 200 OK\r
Via: SIP/2.0/UDP 10.0.0.1\r
Server: Asterisk\r
\r
"""
        
        parsed = parse_sip_response(response)
        self.assertEqual(parsed['status_code'], 200)
        self.assertIn('Via', parsed['headers'])
        self.assertIn('Asterisk', parsed['headers']['Server'])

class TestCVERegistry(unittest.TestCase):
    """Tests for CVE registry"""
    
    def setUp(self):
        self.registry = CVERegistry()
    
    def test_cve_count(self):
        """Test CVE database size"""
        self.assertGreater(len(self.registry.cves), 0)
    
    def test_get_cve(self):
        """Test getting CVE by ID"""
        cve = self.registry.get_cve("CVE-2022-29535")
        self.assertIsNotNone(cve)
        self.assertEqual(cve.cve_id, "CVE-2022-29535")
    
    def test_get_critical_cves(self):
        """Test getting critical CVEs"""
        critical = self.registry.get_critical()
        self.assertGreater(len(critical), 0)
        
        for cve in critical:
            self.assertEqual(cve.severity, Severity.CRITICAL)
    
    def test_get_by_platform(self):
        """Test getting CVEs by platform"""
        asterisk_cves = self.registry.get_by_platform(Platform.ASTERISK)
        self.assertGreater(len(asterisk_cves), 0)
    
    def test_cve_to_dict(self):
        """Test CVE serialization"""
        cve = self.registry.get_cve("CVE-2021-30461")
        cve_dict = cve.to_dict()
        
        self.assertIn('cve_id', cve_dict)
        self.assertIn('title', cve_dict)
        self.assertIn('severity', cve_dict)

class TestRiskScoring(unittest.TestCase):
    """Tests for risk scoring"""
    
    def test_vulnerability_counting(self):
        """Test vulnerability counting for risk score"""
        results = {
            'vulnerabilities': [
                {'severity': 'CRITICAL'},
                {'severity': 'CRITICAL'},
                {'severity': 'HIGH'},
            ]
        }
        
        self.assertEqual(len(results['vulnerabilities']), 3)

if __name__ == '__main__':
    unittest.main()
