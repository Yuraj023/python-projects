"""
analyzer.py
-----------
This module analyzes parsed log data to detect security threats and suspicious patterns.
It identifies failed login attempts, suspicious IPs, and off-hours access.
"""

from collections import Counter, defaultdict
from datetime import time


class LogAnalyzer:
    """
    Analyzes log entries to detect security threats and suspicious activities.
    """
    
    def __init__(self, log_entries):
        """
        Initialize the analyzer with parsed log entries.
        
        Args:
            log_entries (list): List of parsed log dictionaries
        """
        self.log_entries = log_entries
        self.failed_login_threshold = 3  # Number of failed attempts to trigger alert
        self.off_hours_start = time(22, 0)  # 10 PM
        self.off_hours_end = time(6, 0)    # 6 AM
        
    def detect_failed_logins(self):
        """
        Detect users and IPs with repeated failed login attempts.
        
        Returns:
            dict: Dictionary with 'by_user' and 'by_ip' keys containing failed attempt counts
        """
        failed_entries = [entry for entry in self.log_entries 
                         if entry['action'] == 'LOGIN_FAILED']
        
        # Count failed attempts by user
        user_failures = Counter([entry['user'] for entry in failed_entries])
        
        # Count failed attempts by IP
        ip_failures = Counter([entry['ip'] for entry in failed_entries])
        
        # Filter only those exceeding threshold
        suspicious_users = {user: count for user, count in user_failures.items() 
                           if count >= self.failed_login_threshold}
        
        suspicious_ips = {ip: count for ip, count in ip_failures.items() 
                         if count >= self.failed_login_threshold}
        
        print(f"✓ Detected {len(suspicious_users)} users with repeated failed logins")
        print(f"✓ Detected {len(suspicious_ips)} suspicious IPs with failed attempts")
        
        return {
            'by_user': suspicious_users,
            'by_ip': suspicious_ips,
            'total_failed': len(failed_entries)
        }
    
    def detect_suspicious_ips(self):
        """
        Identify IPs with suspicious patterns (multiple failed attempts, diverse users).
        
        Returns:
            dict: IP addresses with their activity details
        """
        ip_activity = defaultdict(lambda: {
            'failed_attempts': 0,
            'users_targeted': set(),
            'timestamps': []
        })
        
        # Analyze each log entry
        for entry in self.log_entries:
            ip = entry['ip']
            
            if entry['action'] == 'LOGIN_FAILED':
                ip_activity[ip]['failed_attempts'] += 1
                ip_activity[ip]['users_targeted'].add(entry['user'])
                ip_activity[ip]['timestamps'].append(entry['timestamp'])
        
        # Filter suspicious IPs (those trying multiple users or excessive attempts)
        suspicious_ips = {}
        
        for ip, activity in ip_activity.items():
            # Suspicious if: 3+ failed attempts OR targeting 2+ different users
            if activity['failed_attempts'] >= 3 or len(activity['users_targeted']) >= 2:
                suspicious_ips[ip] = {
                    'failed_attempts': activity['failed_attempts'],
                    'users_targeted': list(activity['users_targeted']),
                    'user_count': len(activity['users_targeted']),
                    'first_seen': min(activity['timestamps']) if activity['timestamps'] else None,
                    'last_seen': max(activity['timestamps']) if activity['timestamps'] else None
                }
        
        print(f"✓ Identified {len(suspicious_ips)} suspicious IP addresses")
        
        return suspicious_ips
    
    def detect_off_hours_access(self):
        """
        Detect login attempts during off-hours (10 PM to 6 AM).
        
        Returns:
            list: Log entries during off-hours
        """
        off_hours_entries = []
        
        for entry in self.log_entries:
            if entry['timestamp']:
                entry_time = entry['timestamp'].time()
                
                # Check if time is in off-hours range
                if entry_time >= self.off_hours_start or entry_time <= self.off_hours_end:
                    off_hours_entries.append(entry)
        
        print(f"✓ Found {len(off_hours_entries)} off-hours access attempts")
        
        return off_hours_entries
    
    def get_ip_geolocation_estimate(self, ip):
        """
        Estimate if an IP is likely suspicious based on pattern.
        (In production, you'd use an actual geolocation API)
        
        Args:
            ip (str): IP address
            
        Returns:
            str: Risk level estimation
        """
        # Simple heuristic: IPs starting with certain ranges are often suspicious
        # This is a simplified example - real systems use geolocation databases
        
        suspicious_ranges = ['203.0.113', '198.51.100', '185.220', '92.118', 
                            '103.54', '45.76']
        
        for suspicious_range in suspicious_ranges:
            if ip.startswith(suspicious_range):
                return "HIGH_RISK"
        
        # Local network IPs
        if ip.startswith('192.168') or ip.startswith('10.') or ip.startswith('172.'):
            return "LOW_RISK"
        
        return "MEDIUM_RISK"
    
    def generate_security_summary(self):
        """
        Generate a comprehensive security analysis summary.
        
        Returns:
            dict: Complete analysis results
        """
        print("\n" + "="*60)
        print("SECURITY ANALYSIS REPORT")
        print("="*60)
        
        # Get all analysis results
        failed_logins = self.detect_failed_logins()
        suspicious_ips = self.detect_suspicious_ips()
        off_hours = self.detect_off_hours_access()
        
        # Calculate statistics
        total_entries = len(self.log_entries)
        successful_logins = len([e for e in self.log_entries if e['action'] == 'LOGIN_SUCCESS'])
        
        summary = {
            'total_entries': total_entries,
            'successful_logins': successful_logins,
            'failed_logins': failed_logins,
            'suspicious_ips': suspicious_ips,
            'off_hours_access': off_hours,
            'unique_users': len(set(e['user'] for e in self.log_entries)),
            'unique_ips': len(set(e['ip'] for e in self.log_entries))
        }
        
        print(f"\n📊 Total Log Entries: {total_entries}")
        print(f"✓ Successful Logins: {successful_logins}")
        print(f"✗ Failed Login Attempts: {failed_logins['total_failed']}")
        print(f"⚠ Suspicious IPs Detected: {len(suspicious_ips)}")
        print(f"🌙 Off-Hours Access Attempts: {len(off_hours)}")
        print(f"👥 Unique Users: {summary['unique_users']}")
        print(f"🌐 Unique IP Addresses: {summary['unique_ips']}")
        print("="*60 + "\n")
        
        return summary


# Test function
if __name__ == "__main__":
    # This would normally import from log_reader
    print("Analyzer module loaded successfully!")
    print("Import this module in main.py to use its functionality.")
