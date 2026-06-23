#!/usr/bin/env python3
"""
TLS/SSL Security Analysis
Analyzes TLS/SSL configuration and cipher strength
"""

import socket
import ssl
import logging
from typing import Dict, List
import subprocess

logger = logging.getLogger(__name__)

class TLSAnalyzer:
    """Analyzes TLS/SSL security configuration"""
    
    # Known weak ciphers
    WEAK_CIPHERS = [
        'EXPORT', 'DES', 'RC4', 'MD5', 'NULL', 'ANULL', 'EAULL'
    ]
    
    # Strong ciphers
    STRONG_CIPHERS = [
        'AES-256-GCM', 'AES-128-GCM', 'CHACHA20', 'AES-256-CBC'
    ]
    
    def __init__(self, target_host: str, target_port: int = 5061):
        self.target_host = target_host
        self.target_port = target_port
    
    def get_certificate_info(self) -> Dict:
        """Get TLS certificate information"""
        logger.info(f"Fetching certificate from {self.target_host}:{self.target_port}")
        
        result = {
            'certificate': None,
            'issuer': None,
            'subject': None,
            'valid_from': None,
            'valid_until': None,
            'expired': False,
            'self_signed': False,
            'error': None
        }
        
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((self.target_host, self.target_port), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=self.target_host) as ssock:
                    cert = ssock.getpeercert()
                    cert_der = ssock.getpeercert(binary_form=True)
                    
                    if cert:
                        result['certificate'] = cert
                        result['subject'] = dict(x[0] for x in cert.get('subject', []))
                        result['issuer'] = dict(x[0] for x in cert.get('issuer', []))
                        result['valid_from'] = cert.get('notBefore')
                        result['valid_until'] = cert.get('notAfter')
                        
                        # Check if self-signed
                        if result['subject'] == result['issuer']:
                            result['self_signed'] = True
        except Exception as e:
            result['error'] = str(e)
            logger.error(f"Certificate fetch error: {e}")
        
        return result
    
    def test_tls_versions(self) -> Dict:
        """Test supported TLS versions"""
        logger.info("Testing TLS versions")
        
        result = {
            'ssl_v2': False,
            'ssl_v3': False,
            'tls_v1_0': False,
            'tls_v1_1': False,
            'tls_v1_2': False,
            'tls_v1_3': False,
            'weak_versions': [],
            'strong_versions': []
        }
        
        versions = [
            ('ssl_v2', ssl.PROTOCOL_SSLv2 if hasattr(ssl, 'PROTOCOL_SSLv2') else None),
            ('ssl_v3', ssl.PROTOCOL_SSLv3 if hasattr(ssl, 'PROTOCOL_SSLv3') else None),
            ('tls_v1_0', ssl.PROTOCOL_TLSv1 if hasattr(ssl, 'PROTOCOL_TLSv1') else None),
            ('tls_v1_1', ssl.PROTOCOL_TLSv1_1 if hasattr(ssl, 'PROTOCOL_TLSv1_1') else None),
            ('tls_v1_2', ssl.PROTOCOL_TLSv1_2 if hasattr(ssl, 'PROTOCOL_TLSv1_2') else None),
            ('tls_v1_3', ssl.PROTOCOL_TLS if hasattr(ssl, 'PROTOCOL_TLS') else None),
        ]
        
        for version_name, protocol in versions:
            if protocol is None:
                continue
            
            try:
                context = ssl.SSLContext(protocol)
                with socket.create_connection((self.target_host, self.target_port), timeout=2) as sock:
                    with context.wrap_socket(sock, server_hostname=self.target_host) as ssock:
                        result[version_name] = True
                        
                        if version_name in ['ssl_v2', 'ssl_v3', 'tls_v1_0', 'tls_v1_1']:
                            result['weak_versions'].append(version_name)
                        else:
                            result['strong_versions'].append(version_name)
            except:
                pass
        
        return result
    
    def test_cipher_suites(self) -> Dict:
        """Test supported cipher suites"""
        logger.info("Testing cipher suites")
        
        result = {
            'supported_ciphers': [],
            'weak_ciphers': [],
            'strong_ciphers': [],
            'export_ciphers': False
        }
        
        try:
            # Try to get cipher list using openssl
            output = subprocess.check_output(
                ['openssl', 's_client', '-connect', f'{self.target_host}:{self.target_port}', '-cipher', 'ALL'],
                stderr=subprocess.DEVNULL,
                input=b'\n',
                timeout=5
            ).decode()
            
            for line in output.split('\n'):
                if 'Cipher' in line and ':' in line:
                    cipher = line.split(':')[1].strip()
                    result['supported_ciphers'].append(cipher)
                    
                    # Classify cipher
                    if any(weak in cipher for weak in self.WEAK_CIPHERS):
                        result['weak_ciphers'].append(cipher)
                        if 'EXPORT' in cipher:
                            result['export_ciphers'] = True
                    elif any(strong in cipher for strong in self.STRONG_CIPHERS):
                        result['strong_ciphers'].append(cipher)
        except Exception as e:
            logger.debug(f"Cipher suite test error: {e}")
        
        return result
    
    def comprehensive_tls_analysis(self) -> Dict:
        """Comprehensive TLS/SSL analysis"""
        logger.info("Starting TLS/SSL security analysis")
        
        result = {
            'certificate': self.get_certificate_info(),
            'tls_versions': self.test_tls_versions(),
            'ciphers': self.test_cipher_suites(),
            'security_assessment': 'UNKNOWN',
            'vulnerabilities': [],
            'recommendations': []
        }
        
        # Assess security
        if result['tls_versions']['weak_versions']:
            result['vulnerabilities'].append(f"Weak TLS versions supported: {result['tls_versions']['weak_versions']}")
            result['recommendations'].append('Disable TLS 1.0 and 1.1')
        
        if result['ciphers']['weak_ciphers']:
            result['vulnerabilities'].append(f"Weak ciphers supported: {result['ciphers']['weak_ciphers']}")
            result['recommendations'].append('Disable weak ciphers')
        
        if result['certificate']['self_signed']:
            result['vulnerabilities'].append('Self-signed certificate detected')
            result['recommendations'].append('Use CA-signed certificate')
        
        if result['certificate']['error']:
            result['vulnerabilities'].append(f"TLS not available: {result['certificate']['error']}")
        
        if not result['vulnerabilities']:
            result['security_assessment'] = 'SECURE'
        elif len(result['vulnerabilities']) <= 2:
            result['security_assessment'] = 'WEAK'
        else:
            result['security_assessment'] = 'CRITICAL'
        
        return result
