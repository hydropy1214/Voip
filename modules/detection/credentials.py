#!/usr/bin/env python3
"""
Credential Testing Module
Tests for weak, default, and common credentials
"""

import logging
from typing import List, Dict, Tuple
from modules.core.sip_protocol import SIPClient, parse_sip_response
import hashlib
import base64

logger = logging.getLogger(__name__)

class CredentialTester:
    """Tests for weak and default credentials"""
    
    # Common default credentials for VoIP systems
    DEFAULT_CREDENTIALS = [
        ('admin', 'admin'),
        ('admin', 'password'),
        ('admin', '1234'),
        ('admin', '12345'),
        ('admin', '123456'),
        ('admin', ''),
        ('root', 'root'),
        ('root', 'password'),
        ('guest', 'guest'),
        ('operator', 'operator'),
    ]
    
    # Common extensions and weak passwords
    EXTENSION_PASSWORDS = {
        '100': ['100', '1234', 'password', ''],
        '101': ['101', '1234', 'password', ''],
        '110': ['110', '1234', 'password', ''],
        '200': ['200', '1234', 'password', ''],
        '201': ['201', '1234', 'password', ''],
        '2000': ['2000', '1234', 'password', ''],
        '8000': ['8000', '1234', 'password', ''],
    }
    
    def __init__(self, target_host: str, target_port: int = 5060, timeout: int = 5):
        self.target_host = target_host
        self.target_port = target_port
        self.timeout = timeout
        self.sip_client = SIPClient(target_host, target_port, timeout)
        self.weak_credentials = []
    
    def test_http_default_creds(self, http_port: int = 80) -> List[Dict]:
        """Test default credentials on HTTP interface"""
        results = []
        logger.info(f"Testing HTTP default credentials on port {http_port}")
        
        for username, password in self.DEFAULT_CREDENTIALS:
            try:
                import requests
                creds = base64.b64encode(f"{username}:{password}".encode()).decode()
                headers = {'Authorization': f'Basic {creds}'}
                
                response = requests.get(
                    f"http://{self.target_host}:{http_port}/",
                    headers=headers,
                    timeout=self.timeout
                )
                
                if response.status_code == 200:
                    results.append({
                        'type': 'HTTP_AUTH',
                        'username': username,
                        'password': password,
                        'status': 'VULNERABLE',
                        'status_code': response.status_code
                    })
                    logger.warning(f"Found valid HTTP credentials: {username}:{password}")
            except Exception as e:
                logger.debug(f"HTTP auth test failed: {e}")
        
        return results
    
    def test_sip_registration(self, extensions: List[str] = None, passwords: List[str] = None) -> List[Dict]:
        """Test SIP registration with weak credentials"""
        if not extensions:
            extensions = list(self.EXTENSION_PASSWORDS.keys())
        
        results = []
        logger.info(f"Testing SIP registration with {len(extensions)} extensions")
        
        for ext in extensions:
            ext_passwords = passwords or self.EXTENSION_PASSWORDS.get(ext, ['1234', 'password'])
            
            for pwd in ext_passwords:
                try:
                    response = self.sip_client.send_register(ext, pwd)
                    if response:
                        parsed = parse_sip_response(response)
                        status_code = parsed.get('status_code', 0)
                        
                        # 200 OK = Successful registration
                        if status_code == 200:
                            results.append({
                                'type': 'SIP_REGISTRATION',
                                'extension': ext,
                                'password': pwd,
                                'status': 'VULNERABLE',
                                'status_code': status_code,
                                'severity': 'CRITICAL'
                            })
                            logger.warning(f"Found valid SIP registration: {ext}:{pwd}")
                except Exception as e:
                    logger.debug(f"SIP registration test failed for {ext}: {e}")
        
        return results
    
    def test_freeswitch_default_password(self, socket_port: int = 8021) -> Dict:
        """Test FreeSWITCH default ClueCon password"""
        logger.info(f"Testing FreeSWITCH default password on port {socket_port}")
        result = {
            'type': 'FREESWITCH_EVENT_SOCKET',
            'password': 'ClueCon',
            'status': 'SAFE',
            'vulnerable': False
        }
        
        try:
            sock = socket.socket()
            sock.settimeout(self.timeout)
            sock.connect((self.target_host, socket_port))
            
            # Receive welcome message
            welcome = sock.recv(1024)
            
            # Send auth command
            sock.send(b'auth ClueCon\n')
            response = sock.recv(1024)
            
            if b'+OK' in response:
                result['status'] = 'VULNERABLE'
                result['vulnerable'] = True
                logger.warning("FreeSWITCH default password accepted!")
            
            sock.close()
        except Exception as e:
            logger.debug(f"FreeSWITCH test failed: {e}")
        
        return result
    
    def test_ssh_default_creds(self, ssh_port: int = 22) -> List[Dict]:
        """Test SSH default credentials"""
        results = []
        logger.info(f"Testing SSH default credentials on port {ssh_port}")
        
        try:
            import paramiko
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            for username, password in self.DEFAULT_CREDENTIALS:
                try:
                    ssh.connect(
                        self.target_host,
                        port=ssh_port,
                        username=username,
                        password=password,
                        timeout=self.timeout,
                        allow_agent=False,
                        look_for_keys=False
                    )
                    
                    results.append({
                        'type': 'SSH_AUTH',
                        'username': username,
                        'password': password,
                        'status': 'VULNERABLE',
                        'severity': 'CRITICAL'
                    })
                    logger.warning(f"Found valid SSH credentials: {username}:{password}")
                    ssh.close()
                except:
                    pass
        except ImportError:
            logger.debug("Paramiko not available for SSH testing")
        except Exception as e:
            logger.debug(f"SSH testing error: {e}")
        
        return results
    
    def test_telnet_default_creds(self, telnet_port: int = 23) -> List[Dict]:
        """Test Telnet default credentials"""
        results = []
        logger.info(f"Testing Telnet default credentials on port {telnet_port}")
        
        try:
            import socket
            import time
            
            for username, password in self.DEFAULT_CREDENTIALS:
                try:
                    sock = socket.socket()
                    sock.settimeout(self.timeout)
                    sock.connect((self.target_host, telnet_port))
                    
                    # Read login prompt
                    data = sock.recv(1024)
                    time.sleep(0.2)
                    
                    # Send username
                    sock.send((username + "\n").encode())
                    time.sleep(0.2)
                    data = sock.recv(1024)
                    
                    # Send password
                    sock.send((password + "\n").encode())
                    time.sleep(0.5)
                    data = sock.recv(1024)
                    
                    # Check for success indicators
                    if b'#' in data or b'>' in data or b'$' in data:
                        results.append({
                            'type': 'TELNET_AUTH',
                            'username': username,
                            'password': password,
                            'status': 'VULNERABLE',
                            'severity': 'CRITICAL'
                        })
                        logger.warning(f"Found valid Telnet credentials: {username}:{password}")
                    
                    sock.close()
                except:
                    pass
        except Exception as e:
            logger.debug(f"Telnet testing error: {e}")
        
        return results
    
    def comprehensive_credential_test(self) -> Dict:
        """Run all credential tests"""
        logger.info("Starting comprehensive credential testing")
        
        results = {
            'http_credentials': self.test_http_default_creds(),
            'sip_registrations': self.test_sip_registration(),
            'freeswitch': self.test_freeswitch_default_password(),
            'ssh_credentials': self.test_ssh_default_creds(),
            'telnet_credentials': self.test_telnet_default_creds(),
            'summary': {
                'total_vulnerabilities': 0,
                'critical': 0,
                'high': 0
            }
        }
        
        # Count vulnerabilities
        for test_type in ['http_credentials', 'sip_registrations', 'ssh_credentials', 'telnet_credentials']:
            for vuln in results.get(test_type, []):
                if vuln.get('status') == 'VULNERABLE':
                    results['summary']['total_vulnerabilities'] += 1
                    if vuln.get('severity') == 'CRITICAL':
                        results['summary']['critical'] += 1
        
        if results['freeswitch'].get('vulnerable'):
            results['summary']['total_vulnerabilities'] += 1
            results['summary']['critical'] += 1
        
        return results
    
    def close(self):
        """Close connections"""
        self.sip_client.close()
