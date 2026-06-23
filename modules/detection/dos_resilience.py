#!/usr/bin/env python3
"""
DoS/DDoS Resilience Testing
Tests service resilience against denial of service attacks
"""

import socket
import time
import logging
from typing import Dict, List
from concurrent.futures import ThreadPoolExecutor, as_completed
from modules.core.sip_protocol import SIPClient, SIPMessage

logger = logging.getLogger(__name__)

class DOSResilienceTester:
    """Tests DoS resilience of VoIP systems"""
    
    def __init__(self, target_host: str, target_port: int = 5060, timeout: int = 5):
        self.target_host = target_host
        self.target_port = target_port
        self.timeout = timeout
        self.sip_client = SIPClient(target_host, target_port, timeout)
    
    def test_sip_flood(self, packet_count: int = 100, threads: int = 5) -> Dict:
        """Test SIP flood resilience"""
        logger.info(f"Testing SIP flood with {packet_count} packets ({threads} threads)")
        
        result = {
            'test': 'SIP_FLOOD',
            'packets_sent': 0,
            'packets_received': 0,
            'responses': 0,
            'success_rate': 0.0,
            'resilient': False,
            'downtime': False
        }
        
        start_time = time.time()
        
        def send_sip_message(msg_id: int):
            try:
                message = SIPMessage(
                    method="INVITE",
                    uri=f"sip:test{msg_id}@{self.target_host}",
                    headers={
                        "Via": f"SIP/2.0/UDP 10.0.0.1;branch=z9hG4bK-flood{msg_id}",
                        "From": f"<sip:test@{self.target_host}>;tag=flood{msg_id}",
                        "To": f"<sip:test{msg_id}@{self.target_host}>",
                        "Call-ID": f"flood{msg_id}@10.0.0.1",
                        "CSeq": f"{msg_id} INVITE",
                        "Contact": f"<sip:test@10.0.0.1>",
                        "Content-Length": "0"
                    }
                )
                
                response = self.sip_client.send_message(message)
                return response is not None
            except Exception as e:
                logger.debug(f"Flood message {msg_id} error: {e}")
                return False
        
        received_count = 0
        with ThreadPoolExecutor(max_workers=threads) as executor:
            futures = [executor.submit(send_sip_message, i) for i in range(packet_count)]
            
            for future in as_completed(futures):
                result['packets_sent'] += 1
                if future.result():
                    received_count += 1
        
        result['packets_received'] = received_count
        result['responses'] = received_count
        result['success_rate'] = (received_count / packet_count) * 100 if packet_count > 0 else 0
        
        # Check if service is still responding
        time.sleep(2)
        try:
            response = self.sip_client.send_options()
            result['resilient'] = response is not None
        except:
            result['resilient'] = False
            result['downtime'] = True
        
        elapsed = time.time() - start_time
        result['duration'] = elapsed
        result['packets_per_second'] = result['packets_sent'] / elapsed if elapsed > 0 else 0
        
        logger.info(f"SIP flood test complete: {result['success_rate']:.1f}% success rate")
        return result
    
    def test_malformed_packets(self) -> Dict:
        """Test handling of malformed SIP packets"""
        logger.info("Testing malformed packet handling")
        
        result = {
            'test': 'MALFORMED_PACKETS',
            'tests_run': 0,
            'crash_detected': False,
            'errors': [],
            'details': []
        }
        
        malformed_packets = [
            (b'INVALID_METHOD invalid URI\r\n\r\n', 'Invalid method'),
            (b'INVITE\r\n\r\n', 'Missing URI'),
            (b'INVITE sip:test SIP/9.9\r\n\r\n', 'Invalid version'),
            (b'INVITE sip:test@' + (b'A' * 4000) + b' SIP/2.0\r\n\r\n', 'Oversized header'),
            (b'\x00\x01\x02\x03\x04\x05', 'Binary garbage'),
        ]
        
        for packet_data, description in malformed_packets:
            result['tests_run'] += 1
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.settimeout(self.timeout)
                sock.sendto(packet_data, (self.target_host, self.target_port))
                
                try:
                    response = sock.recv(1024)
                    result['details'].append({
                        'test': description,
                        'response': 'Responded',
                        'status': 'OK'
                    })
                except socket.timeout:
                    result['details'].append({
                        'test': description,
                        'response': 'No response',
                        'status': 'Timeout'
                    })
                
                sock.close()
            except Exception as e:
                result['errors'].append(f"{description}: {str(e)}")
                logger.error(f"Malformed packet test error: {e}")
        
        # Check if service crashed
        time.sleep(1)
        try:
            response = self.sip_client.send_options()
            result['crash_detected'] = response is None
        except:
            result['crash_detected'] = True
        
        logger.info(f"Malformed packet test complete: crash_detected={result['crash_detected']}")
        return result
    
    def test_slowloris(self, duration: int = 30) -> Dict:
        """Test Slowloris-style DoS (incomplete messages)"""
        logger.info(f"Testing Slowloris attack ({duration}s duration)")
        
        result = {
            'test': 'SLOWLORIS',
            'duration': duration,
            'connections': 0,
            'service_responsive': True,
            'details': []
        }
        
        start_time = time.time()
        sockets = []
        
        try:
            # Create multiple slow connections
            for i in range(5):
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    sock.settimeout(2)
                    
                    # Send partial message
                    partial_msg = f"INVITE sip:test@{self.target_host} SIP/2.0\r\nVia: SIP/2.0/UDP 10.0.0.1\r\nFrom".encode()
                    sock.sendto(partial_msg, (self.target_host, self.target_port))
                    
                    sockets.append(sock)
                    result['connections'] += 1
                except:
                    pass
            
            # Keep connections open
            while time.time() - start_time < duration:
                time.sleep(0.5)
            
            # Close sockets
            for sock in sockets:
                try:
                    sock.close()
                except:
                    pass
        except Exception as e:
            logger.error(f"Slowloris test error: {e}")
        
        # Check if service is still responsive
        try:
            response = self.sip_client.send_options()
            result['service_responsive'] = response is not None
        except:
            result['service_responsive'] = False
        
        logger.info(f"Slowloris test complete: responsive={result['service_responsive']}")
        return result
    
    def test_udp_flooding(self, duration: int = 10, rate: int = 1000) -> Dict:
        """Test UDP flooding resilience"""
        logger.info(f"Testing UDP flooding ({duration}s, {rate} pps)")
        
        result = {
            'test': 'UDP_FLOODING',
            'duration': duration,
            'target_rate': rate,
            'packets_sent': 0,
            'service_up': True,
            'cpu_spike': False
        }
        
        start_time = time.time()
        packet_data = b'X' * 1472  # Near-max UDP payload
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            
            while time.time() - start_time < duration:
                try:
                    sock.sendto(packet_data, (self.target_host, self.target_port))
                    result['packets_sent'] += 1
                    
                    # Rate limiting
                    elapsed = time.time() - start_time
                    expected_sent = (elapsed / duration) * (rate * duration)
                    if result['packets_sent'] > expected_sent:
                        time.sleep(0.001)
                except:
                    break
            
            sock.close()
        except Exception as e:
            logger.error(f"UDP flood test error: {e}")
        
        # Check service
        time.sleep(2)
        try:
            response = self.sip_client.send_options()
            result['service_up'] = response is not None
        except:
            result['service_up'] = False
        
        logger.info(f"UDP flood test complete: service_up={result['service_up']}")
        return result
    
    def comprehensive_dos_test(self) -> Dict:
        """Run all DoS tests"""
        logger.info("Starting comprehensive DoS resilience testing")
        
        results = {
            'sip_flood': self.test_sip_flood(packet_count=50, threads=3),
            'malformed_packets': self.test_malformed_packets(),
            'slowloris': self.test_slowloris(duration=10),
            'udp_flooding': self.test_udp_flooding(duration=5, rate=100),
            'summary': {
                'resilient': True,
                'vulnerabilities': [],
                'risk_level': 'LOW'
            }
        }
        
        # Analyze results
        if results['sip_flood']['crash_detected']:
            results['summary']['vulnerabilities'].append('SIP flood causes crash')
            results['summary']['resilient'] = False
            results['summary']['risk_level'] = 'CRITICAL'
        
        if results['malformed_packets']['crash_detected']:
            results['summary']['vulnerabilities'].append('Malformed packets cause crash')
            results['summary']['resilient'] = False
            results['summary']['risk_level'] = 'CRITICAL'
        
        if not results['slowloris']['service_responsive']:
            results['summary']['vulnerabilities'].append('Slowloris attack succeeds')
            results['summary']['risk_level'] = 'HIGH'
        
        if not results['udp_flooding']['service_up']:
            results['summary']['vulnerabilities'].append('UDP flooding causes downtime')
            results['summary']['risk_level'] = 'HIGH'
        
        return results
    
    def close(self):
        """Close connections"""
        self.sip_client.close()
