"""
alert_manager.py
----------------
This module generates and displays security alerts based on analysis results.
It creates formatted terminal alerts and saves them to files.
"""

import os
from datetime import datetime


class AlertManager:
    """
    Manages security alerts and notifications.
    Generates terminal alerts and saves alert logs.
    """
    
    def __init__(self, output_dir="../output"):
        """
        Initialize the AlertManager.
        
        Args:
            output_dir (str): Directory to save alert files
        """
        self.output_dir = output_dir
        self.alerts = []
        
        # Create output directory if it doesn't exist
        os.makedirs(self.output_dir, exist_ok=True)
    
    def create_alert(self, severity, category, message, details=None):
        """
        Create a new security alert.
        
        Args:
            severity (str): Alert severity (CRITICAL, HIGH, MEDIUM, LOW)
            category (str): Alert category (FAILED_LOGIN, SUSPICIOUS_IP, OFF_HOURS)
            message (str): Alert message
            details (dict): Additional details about the alert
            
        Returns:
            dict: Created alert object
        """
        alert = {
            'timestamp': datetime.now(),
            'severity': severity,
            'category': category,
            'message': message,
            'details': details or {}
        }
        
        self.alerts.append(alert)
        return alert
    
    def display_alert(self, alert):
        """
        Display an alert in the terminal with color coding.
        
        Args:
            alert (dict): Alert object to display
        """
        # Color codes for different severities
        severity_colors = {
            'CRITICAL': '\033[91m',  # Red
            'HIGH': '\033[93m',       # Yellow
            'MEDIUM': '\033[94m',     # Blue
            'LOW': '\033[92m'          # Green
        }
        
        severity_icons = {
            'CRITICAL': '🚨',
            'HIGH': '⚠️',
            'MEDIUM': '⚡',
            'LOW': 'ℹ️'
        }
        
        reset_color = '\033[0m'
        
        severity = alert['severity']
        color = severity_colors.get(severity, '')
        icon = severity_icons.get(severity, '⚠️')
        
        print(f"\n{color}{'='*70}")
        print(f"{icon} SECURITY ALERT - {severity}")
        print(f"{'='*70}{reset_color}")
        print(f"Category: {alert['category']}")
        print(f"Time: {alert['timestamp'].strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"Message: {alert['message']}")
        
        if alert['details']:
            print(f"\nDetails:")
            for key, value in alert['details'].items():
                print(f"  • {key}: {value}")
        
        print(f"{color}{'='*70}{reset_color}\n")
    
    def generate_failed_login_alerts(self, failed_login_data):
        """
        Generate alerts for failed login attempts.
        
        Args:
            failed_login_data (dict): Failed login analysis results
        """
        print("\n🔍 Generating Failed Login Alerts...")
        
        # Alerts for suspicious users
        for user, count in failed_login_data['by_user'].items():
            severity = 'CRITICAL' if count >= 5 else 'HIGH'
            
            alert = self.create_alert(
                severity=severity,
                category='FAILED_LOGIN',
                message=f"User '{user}' has {count} failed login attempts",
                details={
                    'Username': user,
                    'Failed Attempts': count,
                    'Recommendation': 'Consider account lockout or investigation'
                }
            )
            self.display_alert(alert)
        
        # Alerts for suspicious IPs
        for ip, count in failed_login_data['by_ip'].items():
            severity = 'CRITICAL' if count >= 5 else 'HIGH'
            
            alert = self.create_alert(
                severity=severity,
                category='FAILED_LOGIN',
                message=f"IP '{ip}' has {count} failed login attempts",
                details={
                    'IP Address': ip,
                    'Failed Attempts': count,
                    'Recommendation': 'Consider IP blocking or rate limiting'
                }
            )
            self.display_alert(alert)
    
    def generate_suspicious_ip_alerts(self, suspicious_ips):
        """
        Generate alerts for suspicious IP addresses.
        
        Args:
            suspicious_ips (dict): Suspicious IP analysis results
        """
        print("\n🔍 Generating Suspicious IP Alerts...")
        
        for ip, details in suspicious_ips.items():
            # Determine severity based on activity
            if details['failed_attempts'] >= 5 or details['user_count'] >= 3:
                severity = 'CRITICAL'
            elif details['failed_attempts'] >= 3 or details['user_count'] >= 2:
                severity = 'HIGH'
            else:
                severity = 'MEDIUM'
            
            alert = self.create_alert(
                severity=severity,
                category='SUSPICIOUS_IP',
                message=f"Suspicious activity from IP '{ip}'",
                details={
                    'IP Address': ip,
                    'Failed Attempts': details['failed_attempts'],
                    'Users Targeted': ', '.join(details['users_targeted']),
                    'Total Users': details['user_count'],
                    'First Seen': details['first_seen'].strftime('%Y-%m-%d %H:%M:%S') if details['first_seen'] else 'N/A',
                    'Last Seen': details['last_seen'].strftime('%Y-%m-%d %H:%M:%S') if details['last_seen'] else 'N/A',
                    'Recommendation': 'Immediate IP blocking recommended'
                }
            )
            self.display_alert(alert)
    
    def generate_off_hours_alerts(self, off_hours_entries):
        """
        Generate alerts for off-hours access attempts.
        
        Args:
            off_hours_entries (list): Log entries during off-hours
        """
        print("\n🔍 Generating Off-Hours Access Alerts...")
        
        # Group by IP for better analysis
        ip_counts = {}
        for entry in off_hours_entries:
            ip = entry['ip']
            if ip not in ip_counts:
                ip_counts[ip] = []
            ip_counts[ip].append(entry)
        
        for ip, entries in ip_counts.items():
            # Only alert if there are failed attempts during off-hours
            failed_off_hours = [e for e in entries if e['action'] == 'LOGIN_FAILED']
            
            if failed_off_hours:
                severity = 'CRITICAL' if len(failed_off_hours) >= 3 else 'HIGH'
                
                users = list(set(e['user'] for e in failed_off_hours))
                
                alert = self.create_alert(
                    severity=severity,
                    category='OFF_HOURS_ACCESS',
                    message=f"Suspicious off-hours activity from IP '{ip}'",
                    details={
                        'IP Address': ip,
                        'Off-Hours Attempts': len(entries),
                        'Failed Attempts': len(failed_off_hours),
                        'Users Targeted': ', '.join(users),
                        'Recommendation': 'Investigate immediately - possible breach attempt'
                    }
                )
                self.display_alert(alert)
    
    def save_alerts_to_file(self, filename="security_alerts.txt"):
        """
        Save all generated alerts to a text file.
        
        Args:
            filename (str): Name of the output file
            
        Returns:
            str: Path to the saved file
        """
        filepath = os.path.join(self.output_dir, filename)
        
        try:
            with open(filepath, 'w', encoding='utf-8') as file:
                file.write("="*80 + "\n")
                file.write("SECURITY ALERTS LOG\n")
                file.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                file.write("="*80 + "\n\n")
                
                for alert in self.alerts:
                    file.write(f"\n[{alert['severity']}] {alert['category']}\n")
                    file.write(f"Timestamp: {alert['timestamp'].strftime('%Y-%m-%d %H:%M:%S')}\n")
                    file.write(f"Message: {alert['message']}\n")
                    
                    if alert['details']:
                        file.write("Details:\n")
                        for key, value in alert['details'].items():
                            file.write(f"  - {key}: {value}\n")
                    
                    file.write("-"*80 + "\n")
                
                file.write(f"\n\nTotal Alerts: {len(self.alerts)}\n")
                file.write("="*80 + "\n")
            
            print(f"\n✓ Alerts saved to: {filepath}")
            return filepath
            
        except IOError as e:
            print(f"✗ Error saving alerts: {e}")
            return None
    
    def get_alert_summary(self):
        """
        Get a summary of all alerts by severity.
        
        Returns:
            dict: Count of alerts by severity level
        """
        summary = {
            'CRITICAL': 0,
            'HIGH': 0,
            'MEDIUM': 0,
            'LOW': 0
        }
        
        for alert in self.alerts:
            severity = alert['severity']
            if severity in summary:
                summary[severity] += 1
        
        return summary


# Test function
if __name__ == "__main__":
    print("Alert Manager module loaded successfully!")
    print("Import this module in main.py to use its functionality.")
