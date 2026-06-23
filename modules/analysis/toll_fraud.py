#!/usr/bin/env python3
"""
Toll Fraud Risk Assessment
Analyzes risk of toll fraud and unauthorized calling
"""

import logging
from typing import Dict, List
from dataclasses import dataclass

logger = logging.getLogger(__name__)

@dataclass
class PremiumDestination:
    """Premium/risky destination"""
    country_code: str
    country_name: str
    cost_per_minute: float
    risk_level: str  # LOW, MEDIUM, HIGH, CRITICAL

# Premium destinations known for toll fraud
PREMIUM_DESTINATIONS = [
    PremiumDestination('+242', 'Congo', 2.50, 'CRITICAL'),
    PremiumDestination('+243', 'DR Congo', 3.00, 'CRITICAL'),
    PremiumDestination('+992', 'Tajikistan', 2.75, 'CRITICAL'),
    PremiumDestination('+993', 'Turkmenistan', 2.50, 'CRITICAL'),
    PremiumDestination('+53', 'Cuba', 1.80, 'HIGH'),
    PremiumDestination('+870', 'Inmarsat', 5.00, 'CRITICAL'),
    PremiumDestination('+881', 'IMSI', 4.50, 'CRITICAL'),
    PremiumDestination('+882', 'Iridium', 4.00, 'CRITICAL'),
    PremiumDestination('+883', 'Globalstar', 3.50, 'CRITICAL'),
    PremiumDestination('+888', 'UMTS', 3.00, 'HIGH'),
    PremiumDestination('+971', 'UAE', 1.20, 'MEDIUM'),
    PremiumDestination('+971', 'Saudi Arabia', 1.50, 'MEDIUM'),
    PremiumDestination('+974', 'Qatar', 2.00, 'MEDIUM'),
]

class TollFraudAnalyzer:
    """Analyzes toll fraud risk"""
    
    def __init__(self):
        self.premium_destinations = PREMIUM_DESTINATIONS
    
    def calculate_fraud_potential(self, extensions_found: List[str], 
                                 weak_credentials: List[Dict]) -> Dict:
        """Calculate potential toll fraud loss"""
        logger.info("Calculating toll fraud potential")
        
        result = {
            'vulnerable_extensions': len(extensions_found),
            'weak_credentials_found': len(weak_credentials),
            'potential_fraud': False,
            'estimated_monthly_loss': 0.0,
            'estimated_yearly_loss': 0.0,
            'top_risk_destinations': [],
            'recommendations': []
        }
        
        if weak_credentials or extensions_found:
            result['potential_fraud'] = True
        
        # Calculate potential loss
        # Assume 8 hours per day of fraudulent calling to premium destinations
        hours_per_day = 8
        days_per_month = 30
        
        average_cost_per_minute = sum(d.cost_per_minute for d in self.premium_destinations) / len(self.premium_destinations)
        
        minutes_per_month = hours_per_day * 60 * days_per_month
        result['estimated_monthly_loss'] = (minutes_per_month * average_cost_per_minute * 
                                            len(weak_credentials + extensions_found))
        result['estimated_yearly_loss'] = result['estimated_monthly_loss'] * 12
        
        # Top risk destinations
        critical = [d for d in self.premium_destinations if d.risk_level == 'CRITICAL']
        result['top_risk_destinations'] = [{
            'country': d.country_name,
            'code': d.country_code,
            'cost_per_minute': d.cost_per_minute,
            'estimated_monthly_loss': minutes_per_month * d.cost_per_minute * len(weak_credentials + extensions_found)
        } for d in sorted(critical, key=lambda x: x.cost_per_minute, reverse=True)[:5]]
        
        # Recommendations
        if result['potential_fraud']:
            result['recommendations'].append('Block access to premium numbers')
            result['recommendations'].append('Implement rate limiting')
            result['recommendations'].append('Use strong passwords for all extensions')
            result['recommendations'].append('Monitor call logs for suspicious patterns')
            result['recommendations'].append('Implement international calling restrictions')
        
        return result
    
    def analyze_calling_patterns(self, call_logs: List[Dict]) -> Dict:
        """Analyze calling patterns for fraud indicators"""
        logger.info("Analyzing calling patterns")
        
        result = {
            'total_calls': len(call_logs),
            'premium_calls': 0,
            'international_calls': 0,
            'calls_after_hours': 0,
            'fraud_indicators': [],
            'risk_score': 0.0
        }
        
        for call in call_logs:
            destination = call.get('destination', '')
            time_of_day = call.get('time', '')
            
            # Check for premium destinations
            for premium in self.premium_destinations:
                if destination.startswith(premium.country_code):
                    result['premium_calls'] += 1
                    if premium.risk_level in ['CRITICAL', 'HIGH']:
                        result['fraud_indicators'].append(f"Call to {premium.country_name}")
            
            # Check for after-hours calls (fraudulent behavior)
            if self._is_after_hours(time_of_day):
                result['calls_after_hours'] += 1
                result['fraud_indicators'].append("After-hours call")
        
        # Calculate risk score
        result['risk_score'] = (result['premium_calls'] * 0.5 + 
                               result['calls_after_hours'] * 0.3 +
                               len(result['fraud_indicators']) * 0.1) / max(1, result['total_calls'])
        
        return result
    
    def _is_after_hours(self, time_str: str) -> bool:
        """Check if call is during after-hours"""
        try:
            hour = int(time_str.split(':')[0])
            return hour < 6 or hour > 22
        except:
            return False
    
    def comprehensive_fraud_assessment(self, extensions: List[str], 
                                      weak_creds: List[Dict],
                                      call_logs: List[Dict] = None) -> Dict:
        """Comprehensive toll fraud assessment"""
        logger.info("Starting toll fraud assessment")
        
        if call_logs is None:
            call_logs = []
        
        result = {
            'fraud_potential': self.calculate_fraud_potential(extensions, weak_creds),
            'calling_patterns': self.analyze_calling_patterns(call_logs),
            'summary': {
                'fraud_risk': 'LOW',
                'total_risk_score': 0.0,
                'critical_findings': []
            }
        }
        
        # Calculate overall risk
        if result['fraud_potential']['potential_fraud']:
            result['summary']['critical_findings'].append(
                f"Estimated yearly loss: ${result['fraud_potential']['estimated_yearly_loss']:.2f}"
            )
            
            if result['fraud_potential']['estimated_yearly_loss'] > 10000:
                result['summary']['fraud_risk'] = 'CRITICAL'
            elif result['fraud_potential']['estimated_yearly_loss'] > 5000:
                result['summary']['fraud_risk'] = 'HIGH'
            else:
                result['summary']['fraud_risk'] = 'MEDIUM'
        
        result['summary']['total_risk_score'] = result['calling_patterns']['risk_score']
        
        return result
