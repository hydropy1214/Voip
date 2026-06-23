#!/usr/bin/env python3
"""
SIP Protocol Handler
Handles SIP protocol operations, parsing, and message construction
"""

import socket
import re
from typing import Dict, Tuple, Optional
from dataclasses import dataclass
import logging

logger = logging.getLogger(__name__)

@dataclass
class SIPMessage:
    """Represents a SIP message"""
    method: str
    uri: str
    version: str = "SIP/2.0"
    headers: Dict[str, str] = None
    body: str = ""
    
    def __post_init__(self):
        if self.headers is None:
            self.headers = {}
    
    def to_string(self) -> str:
        """Convert SIP message to string representation"""
        lines = [f"{self.method} {self.uri} {self.version}"]
        
        for key, value in self.headers.items():
            lines.append(f"{key}: {value}")
        
        lines.append("")
        if self.body:
            lines.append(self.body)
        
        return "\r\n".join(lines)

class SIPClient:
    """SIP protocol client for sending and receiving SIP messages"""
    
    def __init__(self, target_host: str, target_port: int = 5060, timeout: int = 5):
        self.target_host = target_host
        self.target_port = target_port
        self.timeout = timeout
        self.sock = None
    
    def _create_socket(self):
        """Create UDP socket for SIP communication"""
        if self.sock is None:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.sock.settimeout(self.timeout)
    
    def send_message(self, message: SIPMessage) -> Optional[str]:
        """Send SIP message to target"""
        try:
            self._create_socket()
            msg_str = message.to_string()
            self.sock.sendto(msg_str.encode(), (self.target_host, self.target_port))
            logger.debug(f"Sent SIP message:\n{msg_str}")
            
            # Try to receive response
            try:
                data, addr = self.sock.recvfrom(2048)
                response = data.decode('utf-8', errors='ignore')
                logger.debug(f"Received response from {addr}:\n{response}")
                return response
            except socket.timeout:
                logger.debug("No response received (timeout)")
                return None
        except Exception as e:
            logger.error(f"Error sending SIP message: {e}")
            return None
    
    def send_options(self) -> Optional[str]:
        """Send SIP OPTIONS request (liveness check)"""
        message = SIPMessage(
            method="OPTIONS",
            uri=f"sip:{self.target_host}",
            headers={
                "Via": f"SIP/2.0/UDP 10.255.255.1;branch=z9hG4bK-check",
                "From": f"<sip:check@10.255.255.1>;tag=check",
                "To": f"<sip:{self.target_host}>",
                "Call-ID": f"check@10.255.255.1",
                "CSeq": "1 OPTIONS",
                "Content-Length": "0"
            }
        )
        return self.send_message(message)
    
    def send_register(self, extension: str, password: str = "") -> Optional[str]:
        """Send SIP REGISTER request"""
        message = SIPMessage(
            method="REGISTER",
            uri=f"sip:{self.target_host}",
            headers={
                "Via": f"SIP/2.0/UDP 10.255.255.1;branch=z9hG4bK-reg{extension}",
                "From": f"<sip:{extension}@{self.target_host}>;tag=reg{extension}",
                "To": f"<sip:{extension}@{self.target_host}>",
                "Call-ID": f"reg{extension}@10.255.255.1",
                "CSeq": "1 REGISTER",
                "Contact": f"<sip:{extension}@10.255.255.1>",
                "Content-Length": "0"
            }
        )
        return self.send_message(message)
    
    def send_invite(self, from_ext: str, to_ext: str) -> Optional[str]:
        """Send SIP INVITE request (call initiation)"""
        message = SIPMessage(
            method="INVITE",
            uri=f"sip:{to_ext}@{self.target_host}",
            headers={
                "Via": f"SIP/2.0/UDP 10.255.255.1;branch=z9hG4bK-invite",
                "From": f"<sip:{from_ext}@{self.target_host}>;tag=invite",
                "To": f"<sip:{to_ext}@{self.target_host}>",
                "Call-ID": f"invite@10.255.255.1",
                "CSeq": "1 INVITE",
                "Contact": f"<sip:{from_ext}@10.255.255.1>",
                "Content-Length": "0"
            }
        )
        return self.send_message(message)
    
    def close(self):
        """Close socket connection"""
        if self.sock:
            self.sock.close()
            self.sock = None
    
    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

def parse_sip_response(response: str) -> Dict:
    """
    Parse SIP response message
    
    Returns:
        Dictionary with parsed response data
    """
    lines = response.split('\r\n')
    result = {
        'status_line': '',
        'status_code': 0,
        'headers': {},
        'body': ''
    }
    
    if not lines:
        return result
    
    # Parse status line
    status_line = lines[0]
    result['status_line'] = status_line
    
    try:
        parts = status_line.split()
        if len(parts) >= 2:
            result['status_code'] = int(parts[1])
    except ValueError:
        pass
    
    # Parse headers
    in_body = False
    for line in lines[1:]:
        if line == '':
            in_body = True
            continue
        
        if in_body:
            result['body'] += line + '\n'
        else:
            if ':' in line:
                key, value = line.split(':', 1)
                result['headers'][key.strip()] = value.strip()
    
    return result
