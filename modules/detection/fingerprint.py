#!/usr/bin/env python3
"""
VoIP Service Fingerprinting
Detects VoIP platforms, versions, and capabilities
"""

import socket
import re
from typing import Dict, Optional, List
import logging
from modules.core.sip_protocol import SIPClient, parse_sip_response

logger = logging.getLogger(__name__)

class VoIPFingerprinter:
    """Fingerprints VoIP systems to identify platform and version"""
    
    def __init__(self, target_host: str, target_port: int = 5060):
        self.target_host = target_host
        self.target_port = target_port
        self.sip_client = SIPClient(target_host, target_port)
        self.fingerprint_data = {}
    
    def get_server_banner(self) -> Optional[str]:
        """Extract Server header from SIP response"""
        try:
            response = self.sip_client.send_options()
            if response:
                parsed = parse_sip_response(response)
                return parsed['headers'].get('Server', None)
        except Exception as e:
            logger.error(f"Error getting server banner: {e}")
        return None
    
    def get_user_agent(self) -> Optional[str]:
        """Extract User-Agent header from SIP response"""
        try:
            response = self.sip_client.send_options()
            if response:
                parsed = parse_sip_response(response)
                return parsed['headers'].get('User-Agent', None)
        except Exception as e:
            logger.error(f"Error getting user agent: {e}")
        return None
    
    def detect_platform(self) -> Dict:
        """Detect VoIP platform based on banners and responses"""
        fingerprint = {
            'platform': None,
            'version': None,
            'banner': None,
            'user_agent': None,
            'allowed_methods': [],
            'confidence': 0.0
        }
        
        # Get banners
        banner = self.get_server_banner()
        user_agent = self.get_user_agent()
        
        fingerprint['banner'] = banner
        fingerprint['user_agent'] = user_agent
        
        # Platform detection signatures
        signatures = {
            'Asterisk': {
                'patterns': [r'Asterisk', r'asterisk'],
                'platform': 'Asterisk',
                'confidence': 0.95
            },
            'FreePBX': {
                'patterns': [r'FreePBX', r'freepbx'],
                'platform': 'FreePBX',
                'confidence': 0.95
            },
            '3CX': {
                'patterns': [r'3CX', r'3cx'],
                'platform': '3CX',
                'confidence': 0.95
            },
            'Cisco': {
                'patterns': [r'Cisco', r'cisco', r'CIPC'],
                'platform': 'Cisco',
                'confidence': 0.9
            },
            'Grandstream': {
                'patterns': [r'Grandstream', r'GXP', r'UCM'],
                'platform': 'Grandstream',
                'confidence': 0.9
            },
            'Avaya': {
                'patterns': [r'Avaya', r'avaya'],
                'platform': 'Avaya',
                'confidence': 0.9
            },
            'Polycom': {
                'patterns': [r'Polycom', r'polycom'],
                'platform': 'Polycom',
                'confidence': 0.9
            },
            'Yealink': {
                'patterns': [r'Yealink', r'yealink'],
                'platform': 'Yealink',
                'confidence': 0.9
            },
            'FreeSWITCH': {
                'patterns': [r'FreeSWITCH', r'freeswitch'],
                'platform': 'FreeSWITCH',
                'confidence': 0.95
            }
        }
        
        combined_banner = f"{banner or ''} {user_agent or ''}"
        
        for sig_name, sig_data in signatures.items():
            for pattern in sig_data['patterns']:
                if re.search(pattern, combined_banner, re.IGNORECASE):
                    fingerprint['platform'] = sig_data['platform']
                    fingerprint['confidence'] = sig_data['confidence']
                    
                    # Try to extract version
                    version_match = re.search(r'(?:version|v|/)(\d+\.\d+(?:\.\d+)?)', combined_banner, re.IGNORECASE)
                    if version_match:
                        fingerprint['version'] = version_match.group(1)
                    
                    break
            
            if fingerprint['platform']:
                break
        
        return fingerprint
    
    def detect_allowed_methods(self) -> List[str]:
        """Detect allowed SIP methods"""
        methods = []
        try:
            response = self.sip_client.send_options()
            if response:
                parsed = parse_sip_response(response)
                allow_header = parsed['headers'].get('Allow', '')
                methods = [m.strip() for m in allow_header.split(',') if m.strip()]
        except Exception as e:
            logger.error(f"Error detecting allowed methods: {e}")
        return methods
    
    def detect_extensions(self) -> Dict:
        """Detect common extensions/users"""
        extensions = {
            'found': [],
            'tested': 0
        }
        
        common_extensions = ['100', '101', '102', '110', '200', '201', '2000', '8000', 'admin', 'operator']
        
        for ext in common_extensions:
            extensions['tested'] += 1
            try:
                response = self.sip_client.send_register(ext)
                if response:
                    parsed = parse_sip_response(response)
                    status_code = parsed.get('status_code', 0)
                    
                    # 401 Unauthorized = extension exists
                    # 403 Forbidden = extension exists but auth required
                    # 200 OK = extension exists and registered
                    if status_code in [200, 401, 403]:
                        extensions['found'].append({
                            'extension': ext,
                            'status': status_code,
                            'status_text': parsed['headers'].get('Status', 'Unknown')
                        })
            except Exception as e:
                logger.debug(f"Error testing extension {ext}: {e}")
        
        return extensions
    
    def detect_authentication_methods(self) -> List[str]:
        """Detect supported authentication methods"""
        methods = []
        try:
            response = self.sip_client.send_options()
            if response:
                parsed = parse_sip_response(response)
                www_authenticate = parsed['headers'].get('WWW-Authenticate', '')
                if www_authenticate:
                    if 'Digest' in www_authenticate:
                        methods.append('Digest')
                    if 'Basic' in www_authenticate:
                        methods.append('Basic')
        except Exception as e:
            logger.error(f"Error detecting auth methods: {e}")
        return methods if methods else ['Unknown']
    
    def full_fingerprint(self) -> Dict:
        """Perform complete fingerprinting"""
        logger.info(f"Starting fingerprint of {self.target_host}:{self.target_port}")
        
        result = {
            'target': f"{self.target_host}:{self.target_port}",
            'platform': self.detect_platform(),
            'allowed_methods': self.detect_allowed_methods(),
            'extensions': self.detect_extensions(),
            'auth_methods': self.detect_authentication_methods(),
            'reachable': True
        }
        
        logger.info(f"Fingerprint complete: {result['platform']['platform']}")
        return result
    
    def close(self):
        """Close connections"""
        self.sip_client.close()
