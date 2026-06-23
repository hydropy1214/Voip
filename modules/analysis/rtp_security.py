#!/usr/bin/env python3
"""
RTP/SRTP Security Analysis
Analyzes media stream security and encryption
"""

import socket
import logging
from typing import Dict, List, Tuple
from dataclasses import dataclass

logger = logging.getLogger(__name__)

@dataclass
class RTPPacket:
    """Represents an RTP packet"""
    version: int
    padding: bool
    extension: bool
    csrc_count: int
    marker: bool
    payload_type: int
    sequence_number: int
    timestamp: int
    ssrc: int
    csrc_list: List[int]
    
    def is_encrypted(self) -> bool:
        """Determine if packet appears encrypted based on payload"""
        return False  # Simplified - real implementation would check for patterns

class RTPSecurityAnalyzer:
    """Analyzes RTP/SRTP security"""
    
    def __init__(self, target_host: str, listen_port: int = 5000):
        self.target_host = target_host
        self.listen_port = listen_port
        self.packets_captured = []
    
    def capture_rtp_packets(self, duration: int = 30, packet_limit: int = 1000) -> List[Dict]:
        """Capture RTP packets"""
        logger.info(f"Capturing RTP packets for {duration} seconds")
        
        packets = []
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.bind(('0.0.0.0', self.listen_port))
            sock.settimeout(1)
            
            import time
            start_time = time.time()
            
            while time.time() - start_time < duration and len(packets) < packet_limit:
                try:
                    data, addr = sock.recvfrom(4096)
                    
                    if len(data) >= 12:  # Minimum RTP header size
                        packet_info = self.parse_rtp_packet(data, addr)
                        if packet_info:
                            packets.append(packet_info)
                except socket.timeout:
                    continue
            
            sock.close()
        except Exception as e:
            logger.error(f"RTP capture error: {e}")
        
        logger.info(f"Captured {len(packets)} RTP packets")
        return packets
    
    def parse_rtp_packet(self, data: bytes, source: Tuple) -> Dict:
        """Parse RTP packet"""
        if len(data) < 12:
            return None
        
        try:
            # Parse fixed header
            first_byte = data[0]
            version = (first_byte >> 6) & 0x3
            padding = bool((first_byte >> 5) & 0x1)
            extension = bool((first_byte >> 4) & 0x1)
            csrc_count = first_byte & 0xF
            
            second_byte = data[1]
            marker = bool((second_byte >> 7) & 0x1)
            payload_type = second_byte & 0x7F
            
            sequence = int.from_bytes(data[2:4], 'big')
            timestamp = int.from_bytes(data[4:8], 'big')
            ssrc = int.from_bytes(data[8:12], 'big')
            
            # Payload type identification
            payload_names = {
                0: 'PCMU',
                8: 'PCMA',
                18: 'G729',
                97: 'MPEG4-GENERIC',
                100: 'Speex',
            }
            
            return {
                'source': source,
                'version': version,
                'padding': padding,
                'extension': extension,
                'csrc_count': csrc_count,
                'marker': marker,
                'payload_type': payload_type,
                'payload_name': payload_names.get(payload_type, f'Unknown({payload_type})'),
                'sequence': sequence,
                'timestamp': timestamp,
                'ssrc': ssrc,
                'size': len(data),
                'encrypted': self.detect_encryption(data[12:])
            }
        except Exception as e:
            logger.debug(f"RTP parse error: {e}")
            return None
    
    def detect_encryption(self, payload: bytes) -> bool:
        """Detect if payload appears encrypted"""
        # Check for patterns that indicate encryption
        # Encrypted data typically has high entropy
        if len(payload) < 16:
            return False
        
        # Simple entropy check
        byte_counts = {}
        for byte in payload[:64]:
            byte_counts[byte] = byte_counts.get(byte, 0) + 1
        
        unique_bytes = len(byte_counts)
        entropy_ratio = unique_bytes / 256
        
        return entropy_ratio > 0.7  # High entropy suggests encryption
    
    def analyze_rtp_security(self, packets: List[Dict]) -> Dict:
        """Analyze RTP security"""
        result = {
            'total_packets': len(packets),
            'encrypted_packets': 0,
            'unencrypted_packets': 0,
            'payload_types': {},
            'sources': set(),
            'security_assessment': 'UNKNOWN',
            'recommendations': []
        }
        
        for packet in packets:
            if packet['encrypted']:
                result['encrypted_packets'] += 1
            else:
                result['unencrypted_packets'] += 1
            
            payload_name = packet['payload_name']
            result['payload_types'][payload_name] = result['payload_types'].get(payload_name, 0) + 1
            result['sources'].add(packet['source'][0])
        
        # Assessment
        if result['unencrypted_packets'] > 0:
            result['security_assessment'] = 'VULNERABLE'
            result['recommendations'].append('Enable SRTP for media encryption')
            result['recommendations'].append('Use TLS for signaling')
        elif result['encrypted_packets'] > 0:
            result['security_assessment'] = 'SECURE'
            result['recommendations'].append('SRTP encryption is in use')
        
        result['sources'] = list(result['sources'])
        return result
    
    def detect_rtp_hijacking(self, packets: List[Dict]) -> Dict:
        """Detect potential RTP hijacking"""
        result = {
            'ssrc_list': set(),
            'source_ips': set(),
            'hijacking_risk': False,
            'anomalies': []
        }
        
        if not packets:
            return result
        
        # Collect SSRCs and sources
        for packet in packets:
            result['ssrc_list'].add(packet['ssrc'])
            result['source_ips'].add(packet['source'][0])
        
        # Check for anomalies
        if len(result['ssrc_list']) > 2:
            result['anomalies'].append(f'Multiple SSRCs detected: {len(result["ssrc_list"])}')
            result['hijacking_risk'] = True
        
        if len(result['source_ips']) > 1:
            result['anomalies'].append(f'Multiple source IPs: {len(result["source_ips"])}')
            result['hijacking_risk'] = True
        
        result['ssrc_list'] = list(result['ssrc_list'])
        return result
    
    def comprehensive_rtp_analysis(self, duration: int = 30) -> Dict:
        """Comprehensive RTP/SRTP analysis"""
        logger.info("Starting RTP/SRTP security analysis")
        
        packets = self.capture_rtp_packets(duration=duration)
        
        result = {
            'packet_analysis': self.analyze_rtp_security(packets),
            'hijacking_analysis': self.detect_rtp_hijacking(packets),
            'summary': {
                'rtp_detected': len(packets) > 0,
                'encrypted': False,
                'risk_level': 'LOW'
            }
        }
        
        if not result['summary']['rtp_detected']:
            result['summary']['risk_level'] = 'INFO'
        else:
            result['summary']['encrypted'] = result['packet_analysis']['unencrypted_packets'] == 0
            
            if result['hijacking_analysis']['hijacking_risk']:
                result['summary']['risk_level'] = 'HIGH'
            elif result['summary']['encrypted']:
                result['summary']['risk_level'] = 'LOW'
            else:
                result['summary']['risk_level'] = 'CRITICAL'
        
        return result
