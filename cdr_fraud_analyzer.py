#!/usr/bin/env python3

"""
ENTERPRISE VOIP CDR ANOMALY DETECTION & TOLL FRAUD ANALYSIS
Production-grade Python script for Asterisk CDR analysis and fraud detection

Features:
- E.164 country code extraction and validation
- Call volume and duration analysis by destination
- Fraud pattern detection
- International call anomaly identification
- Terminal table output with risk scoring
- Comprehensive error handling and logging
"""

import csv
import sys
import json
from collections import defaultdict
from datetime import datetime, timedelta
from typing import Dict, List, Set, Tuple, Optional
import logging

# ============================================================================
# CONFIGURATION
# ============================================================================

# Approved country codes for international dialing
APPROVED_COUNTRY_CODES = {
    "+1": "USA/Canada",
    "+44": "United Kingdom",
    "+61": "Australia",
    "+33": "France",
    "+49": "Germany",
    "+81": "Japan",
    "+86": "China",
    "+39": "Italy",
    "+34": "Spain",
    "+31": "Netherlands",
}

# Fraud detection thresholds
VOLUME_THRESHOLD = 50  # Calls per country code per day
DURATION_THRESHOLD = 500  # Minutes per country code per day
AVERAGE_CALL_DURATION = 3  # Minutes - calls significantly shorter suggest scanning

# Risk scoring parameters
VOLUME_MULTIPLIER = 1.0
DURATION_MULTIPLIER = 1.5
CONCURRENT_MULTIPLIER = 2.0
SHORT_CALL_MULTIPLIER = 0.5

# High-risk countries (known fraud hotspots)
HIGH_RISK_COUNTRIES = {
    "+234": "Nigeria",
    "+27": "South Africa",
    "+212": "Morocco",
    "+94": "Sri Lanka",
    "+880": "Bangladesh",
}

# Logging configuration
LOG_FORMAT = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
LOG_LEVEL = logging.INFO

# ============================================================================
# LOGGING SETUP
# ============================================================================

logger = logging.getLogger(__name__)
handler = logging.StreamHandler(sys.stdout)
formatter = logging.Formatter(LOG_FORMAT)
handler.setFormatter(formatter)
logger.addHandler(handler)
logger.setLevel(LOG_LEVEL)

# ============================================================================
# DATA MODELS & CLASSES
# ============================================================================

class CDRRecord:
    """Represents a single Call Detail Record"""
    
    def __init__(self, calldate: str, src_extension: str, dst_number: str, 
                 duration_seconds: int):
        self.calldate = calldate
        self.src_extension = src_extension
        self.dst_number = dst_number
        self.duration_seconds = duration_seconds
        self.duration_minutes = duration_seconds / 60.0 if duration_seconds > 0 else 0
        
        # Extract date components
        try:
            dt = datetime.strptime(calldate.split()[0], "%Y-%m-%d")
            self.date = dt.date()
            self.hour = dt.hour
        except (ValueError, IndexError):
            self.date = None
            self.hour = None
    
    def is_international(self) -> bool:
        """Check if call is international"""
        return self.dst_number.startswith(("+", "011"))
    
    def get_country_code(self) -> Optional[str]:
        """Extract E.164 country code from destination number"""
        dst = self.dst_number.strip()
        
        # E.164 format with + prefix
        if dst.startswith("+"):
            for length in range(1, 4):
                if length < len(dst):
                    potential_code = dst[:length + 1]
                    if all(c.isdigit() for c in potential_code[1:]):
                        return potential_code
            return dst[:4] if len(dst) >= 4 else dst
        
        # US format (011 prefix for international)
        elif dst.startswith("011"):
            if len(dst) >= 6:
                country_code = dst[3:6]
                if country_code.isdigit():
                    return "+" + country_code
            return None
        
        return None
    
    def __repr__(self):
        return f"CDRRecord({self.calldate}, {self.src_extension}, {self.dst_number}, {self.duration_seconds}s)"


class CountryStatistics:
    """Tracks statistics for a specific country code on a specific date"""
    
    def __init__(self):
        self.calls = 0
        self.total_duration_minutes = 0.0
        self.destinations: Set[str] = set()
        self.short_calls = 0  # Calls < 1 minute
        self.call_timestamps: List[datetime] = []
        self.call_durations: List[int] = []
    
    def add_call(self, duration_seconds: int, dst_number: str, calltime: datetime):
        """Register a call to this country"""
        self.calls += 1
        duration_minutes = duration_seconds / 60.0
        self.total_duration_minutes += duration_minutes
        self.destinations.add(dst_number)
        self.call_timestamps.append(calltime)
        self.call_durations.append(duration_seconds)
        
        if duration_seconds < 60:
            self.short_calls += 1
    
    def get_average_duration(self) -> float:
        """Calculate average call duration in minutes"""
        if self.calls == 0:
            return 0
        return self.total_duration_minutes / self.calls
    
    def get_risk_score(self, is_approved: bool = False) -> float:
        """Calculate risk score for this country/date combination"""
        score = 0.0
        
        # Approved country codes get lower baseline
        if is_approved:
            return max(0, (self.calls - VOLUME_THRESHOLD * 2) / 100.0)
        
        # Volume-based risk
        if self.calls > VOLUME_THRESHOLD:
            score += (self.calls - VOLUME_THRESHOLD) / VOLUME_THRESHOLD * VOLUME_MULTIPLIER
        
        # Duration-based risk
        if self.total_duration_minutes > DURATION_THRESHOLD:
            excess = self.total_duration_minutes - DURATION_THRESHOLD
            score += (excess / DURATION_THRESHOLD) * DURATION_MULTIPLIER
        
        # Short call pattern risk (scanning behavior)
        short_call_ratio = self.short_calls / self.calls if self.calls > 0 else 0
        if short_call_ratio > 0.7:  # >70% short calls
            score += 2.0 * SHORT_CALL_MULTIPLIER
        
        # High-risk country bonus
        if any(dst.startswith(country) for country in HIGH_RISK_COUNTRIES for dst in self.destinations):
            score += 1.5
        
        # Multiple destinations (scatter pattern)
        if self.calls > 10 and len(self.destinations) > self.calls * 0.8:
            score += 1.0
        
        return min(score, 10.0)  # Cap at 10
    
    def __repr__(self):
        return f"CountryStats(calls={self.calls}, duration={self.total_duration_minutes:.1f}m, dests={len(self.destinations)})"


class FraudAnalyzer:
    """Main analyzer for CDR fraud detection"""
    
    def __init__(self, cdr_file: str):
        self.cdr_file = cdr_file
        self.records: List[CDRRecord] = []
        self.country_stats: Dict[str, Dict[str, CountryStatistics]] = defaultdict(dict)
        self.flagged_records: List[Dict] = []
        self.total_records_processed = 0
        self.invalid_records = 0
    
    def load_cdr_data(self) -> bool:
        """Load and parse CDR CSV file"""
        logger.info(f"Loading CDR data from: {self.cdr_file}")
        
        try:
            with open(self.cdr_file, 'r', encoding='utf-8', errors='replace') as f:
                reader = csv.DictReader(f)
                
                if not reader.fieldnames:
                    logger.error("CDR file is empty or missing headers")
                    return False
                
                required_fields = {'calldate', 'src_extension', 'dst_number', 'duration_seconds'}
                if not required_fields.issubset(set(reader.fieldnames or [])):
                    logger.error(f"Missing required fields. Found: {reader.fieldnames}")
                    return False
                
                for row_num, row in enumerate(reader, start=2):
                    try:
                        # Extract and validate fields
                        calldate = row.get('calldate', '').strip()
                        src_ext = row.get('src_extension', '').strip()
                        dst_num = row.get('dst_number', '').strip()
                        duration_str = row.get('duration_seconds', '0').strip()
                        
                        # Validate required fields
                        if not all([calldate, dst_num, duration_str]):
                            self.invalid_records += 1
                            continue
                        
                        # Parse duration
                        try:
                            duration = int(float(duration_str))
                            if duration < 0:
                                raise ValueError("Negative duration")
                        except (ValueError, TypeError):
                            self.invalid_records += 1
                            continue
                        
                        # Create CDR record
                        record = CDRRecord(calldate, src_ext, dst_num, duration)
                        
                        # Validate parsed date
                        if not record.date:
                            self.invalid_records += 1
                            continue
                        
                        self.records.append(record)
                        self.total_records_processed += 1
                        
                    except Exception as e:
                        logger.debug(f"Error processing row {row_num}: {e}")
                        self.invalid_records += 1
                        continue
                
                logger.info(f"Loaded {len(self.records)} valid CDR records")
                logger.info(f"Skipped {self.invalid_records} invalid records")
                
                return len(self.records) > 0
        
        except FileNotFoundError:
            logger.error(f"CDR file not found: {self.cdr_file}")
            return False
        except Exception as e:
            logger.error(f"Error reading CDR file: {e}")
            return False
    
    def analyze_call_patterns(self) -> None:
        """Analyze call patterns and build statistics"""
        logger.info("Analyzing call patterns...")
        
        for record in self.records:
            # Skip non-international calls
            if not record.is_international():
                continue
            
            # Extract country code
            country_code = record.get_country_code()
            if not country_code:
                continue
            
            # Get date key
            date_key = str(record.date) if record.date else "unknown"
            
            # Initialize statistics if needed
            if country_code not in self.country_stats:
                self.country_stats[country_code] = {}
            if date_key not in self.country_stats[country_code]:
                self.country_stats[country_code][date_key] = CountryStatistics()
            
            # Add call to statistics
            calltime = datetime.strptime(record.calldate, "%Y-%m-%d %H:%M:%S") if record.calldate else datetime.now()
            self.country_stats[country_code][date_key].add_call(
                record.duration_seconds,
                record.dst_number,
                calltime
            )
        
        logger.info(f"Analyzed {len(self.country_stats)} unique country codes")
    
    def detect_fraud(self) -> None:
        """Detect fraudulent patterns"""
        logger.info("Detecting fraud patterns...")
        
        for country_code, date_stats in self.country_stats.items():
            is_approved = country_code in APPROVED_COUNTRY_CODES
            
            for date_key, stats in date_stats.items():
                # Check volume threshold
                volume_exceeded = stats.calls >= VOLUME_THRESHOLD and not is_approved
                
                # Check duration threshold
                duration_exceeded = stats.total_duration_minutes >= DURATION_THRESHOLD and not is_approved
                
                # Calculate risk score
                risk_score = stats.get_risk_score(is_approved)
                
                # Flag if suspicious
                if volume_exceeded or duration_exceeded or risk_score > 1.5:
                    self.flagged_records.append({
                        'country_code': country_code,
                        'date': date_key,
                        'calls': stats.calls,
                        'duration_minutes': stats.total_duration_minutes,
                        'unique_destinations': len(stats.destinations),
                        'average_duration': stats.get_average_duration(),
                        'short_calls': stats.short_calls,
                        'risk_score': risk_score,
                        'is_approved': is_approved,
                        'country_name': APPROVED_COUNTRY_CODES.get(country_code, 
                                       HIGH_RISK_COUNTRIES.get(country_code, "Unknown"))
                    })
        
        # Sort by risk score descending
        self.flagged_records.sort(key=lambda x: x['risk_score'], reverse=True)
        logger.info(f"Detected {len(self.flagged_records)} fraud indicators")
    
    def generate_report(self, output_file: str = "fraud_analysis.txt") -> None:
        """Generate human-readable fraud report"""
        logger.info(f"Generating fraud report: {output_file}")
        
        with open(output_file, 'w', encoding='utf-8') as f:
            # Header
            f.write("╔════════════════════════════════════════════════════════════════════╗\n")
            f.write("║         CDR FRAUD ANALYSIS & ANOMALY DETECTION REPORT               ║\n")
            f.write(f"║         Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}                          ║\n")
            f.write("║         Enterprise VoIP Security Framework                          ║\n")
            f.write("╚════════════════════════════════════════════════════════════════════╝\n\n")
            
            # Summary statistics
            f.write("ANALYSIS SUMMARY\n")
            f.write("═" * 70 + "\n")
            f.write(f"Total CDR Records Processed: {self.total_records_processed}\n")
            f.write(f"Valid Records: {len(self.records)}\n")
            f.write(f"Invalid Records: {self.invalid_records}\n")
            f.write(f"International Calls: {sum(1 for r in self.records if r.is_international())}\n")
            f.write(f"Unique Country Codes Detected: {len(self.country_stats)}\n")
            f.write(f"Fraud Indicators Detected: {len(self.flagged_records)}\n")
            f.write(f"Approved Country Codes: {', '.join(APPROVED_COUNTRY_CODES.keys())}\n")
            f.write(f"\nThresholds:\n")
            f.write(f"  Volume Threshold: {VOLUME_THRESHOLD} calls/day\n")
            f.write(f"  Duration Threshold: {DURATION_THRESHOLD} minutes/day\n")
            f.write("\n")
            
            # Flagged records table
            if self.flagged_records:
                f.write("FLAGGED HIGH-RISK DESTINATIONS (Sorted by Risk Score)\n")
                f.write("═" * 70 + "\n")
                f.write(f"{'Country':<12} {'Date':<12} {'Calls':<8} {'Duration':<12} {'Risk':<8}\n")
                f.write("─" * 70 + "\n")
                
                for record in self.flagged_records[:50]:  # Top 50
                    country_display = f"{record['country_code']} {record['country_name'][:15]}"
                    
                    # Risk level visualization
                    risk = record['risk_score']
                    if risk > 7:
                        risk_visual = "🔴 CRITICAL"
                    elif risk > 4:
                        risk_visual = "🟠 HIGH"
                    elif risk > 2:
                        risk_visual = "🟡 MEDIUM"
                    else:
                        risk_visual = "🟢 LOW"
                    
                    f.write(f"{country_display:<12} {record['date']:<12} {record['calls']:<8} "
                           f"{record['duration_minutes']:<12.1f} {risk_visual:<8}\n")
                
                if len(self.flagged_records) > 50:
                    f.write(f"\n... and {len(self.flagged_records) - 50} more flagged records\n")
            else:
                f.write("No fraud indicators detected.\n")
            
            f.write("\n")
            
            # Detailed findings
            if self.flagged_records:
                f.write("DETAILED FINDINGS\n")
                f.write("═" * 70 + "\n\n")
                
                for idx, record in enumerate(self.flagged_records[:10], 1):
                    f.write(f"{idx}. {record['country_code']} - {record['country_name']} ({record['date']})\n")
                    f.write(f"   Call Volume: {record['calls']} calls (threshold: {VOLUME_THRESHOLD})\n")
                    f.write(f"   Total Duration: {record['duration_minutes']:.1f} minutes (threshold: {DURATION_THRESHOLD})\n")
                    f.write(f"   Unique Destinations: {record['unique_destinations']}\n")
                    f.write(f"   Average Call Duration: {record['average_duration']:.2f} minutes\n")
                    f.write(f"   Short Calls (<1 min): {record['short_calls']}\n")
                    f.write(f"   Risk Score: {record['risk_score']:.2f}/10.0\n")
                    
                    if not record['is_approved']:
                        estimated_loss = record['duration_minutes'] * 0.15  # $0.15/min estimate
                        f.write(f"   Estimated Loss (est. $0.15/min): ${estimated_loss:.2f}\n")
                    
                    f.write("\n")
            
            # Recommendations
            f.write("RECOMMENDATIONS\n")
            f.write("═" * 70 + "\n")
            f.write("1. Review flagged destinations for legitimate business need\n")
            f.write("2. Enable call routing restrictions to approved countries only\n")
            f.write("3. Implement rate limiting on international calls\n")
            f.write("4. Monitor accounts with frequent short-duration calls (scanning)\n")
            f.write("5. Deploy real-time fraud detection and alerting\n")
            f.write("6. Conduct user awareness training on toll fraud\n")
            f.write("7. Review and strengthen SIP authentication\n")
            f.write("8. Implement CDR analysis as ongoing security practice\n")
        
        logger.info(f"Report written to: {output_file}")
    
    def generate_json_report(self, output_file: str = "fraud_findings.json") -> None:
        """Generate machine-readable JSON report"""
        logger.info(f"Generating JSON report: {output_file}")
        
        report_data = {
            'metadata': {
                'generated_at': datetime.now().isoformat(),
                'script_version': '1.0.0',
                'total_records': len(self.records),
                'invalid_records': self.invalid_records,
            },
            'statistics': {
                'unique_country_codes': len(self.country_stats),
                'fraud_indicators': len(self.flagged_records),
                'approved_countries': list(APPROVED_COUNTRY_CODES.keys()),
            },
            'thresholds': {
                'volume_threshold': VOLUME_THRESHOLD,
                'duration_threshold': DURATION_THRESHOLD,
            },
            'flagged_records': self.flagged_records[:100],  # Top 100
        }
        
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(report_data, f, indent=2, default=str)
        
        logger.info(f"JSON report written to: {output_file}")


# ============================================================================
# MAIN EXECUTION
# ============================================================================

def main():
    """Main execution function"""
    
    # Parse command line arguments
    cdr_file = sys.argv[1] if len(sys.argv) > 1 else "asterisk_cdr.csv"
    output_file = sys.argv[2] if len(sys.argv) > 2 else "fraud_analysis.txt"
    json_file = sys.argv[3] if len(sys.argv) > 3 else "fraud_findings.json"
    
    logger.info("=" * 70)
    logger.info("CDR FRAUD ANALYSIS & ANOMALY DETECTION")
    logger.info("=" * 70)
    
    # Create analyzer
    analyzer = FraudAnalyzer(cdr_file)
    
    # Load data
    if not analyzer.load_cdr_data():
        logger.error("Failed to load CDR data")
        sys.exit(1)
    
    # Analyze patterns
    analyzer.analyze_call_patterns()
    
    # Detect fraud
    analyzer.detect_fraud()
    
    # Generate reports
    analyzer.generate_report(output_file)
    analyzer.generate_json_report(json_file)
    
    logger.info("Analysis complete")
    logger.info("=" * 70)
    
    # Display summary to stdout
    print("\n" + "=" * 70)
    print("FRAUD ANALYSIS SUMMARY")
    print("=" * 70)
    print(f"Records Processed: {analyzer.total_records_processed}")
    print(f"Fraud Indicators: {len(analyzer.flagged_records)}")
    
    if analyzer.flagged_records:
        print("\nTop 5 Fraud Risks:")
        for record in analyzer.flagged_records[:5]:
            print(f"  {record['country_code']} ({record['country_name']}) - "
                  f"Risk Score: {record['risk_score']:.2f}/10.0")
    
    print("\nReports generated:")
    print(f"  - {output_file}")
    print(f"  - {json_file}")
    print("=" * 70 + "\n")


if __name__ == "__main__":
    main()
