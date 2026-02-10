"""
report_generator.py
-------------------
This module generates comprehensive security analysis reports.
It creates detailed reports in text format with statistics and recommendations.
"""

import os
from datetime import datetime


class ReportGenerator:
    """
    Generates detailed security analysis reports.
    Creates formatted reports with statistics, findings, and recommendations.
    """
    
    def __init__(self, output_dir="../output"):
        """
        Initialize the ReportGenerator.
        
        Args:
            output_dir (str): Directory to save report files
        """
        self.output_dir = output_dir
        
        # Create output directory if it doesn't exist
        os.makedirs(self.output_dir, exist_ok=True)
    
    def generate_summary_report(self, analysis_summary, alert_summary):
        """
        Generate a comprehensive summary report.
        
        Args:
            analysis_summary (dict): Results from LogAnalyzer
            alert_summary (dict): Alert counts by severity
            
        Returns:
            str: Path to the generated report
        """
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"security_report_{timestamp}.txt"
        filepath = os.path.join(self.output_dir, filename)
        
        try:
            with open(filepath, 'w', encoding='utf-8') as file:
                # Header
                file.write("="*80 + "\n")
                file.write("SERVER LOG SECURITY ANALYSIS REPORT\n")
                file.write("="*80 + "\n")
                file.write(f"Report Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                file.write("="*80 + "\n\n")
                
                # Executive Summary
                file.write("EXECUTIVE SUMMARY\n")
                file.write("-"*80 + "\n")
                file.write(f"Total Log Entries Analyzed: {analysis_summary['total_entries']}\n")
                file.write(f"Successful Logins: {analysis_summary['successful_logins']}\n")
                file.write(f"Failed Login Attempts: {analysis_summary['failed_logins']['total_failed']}\n")
                file.write(f"Unique Users: {analysis_summary['unique_users']}\n")
                file.write(f"Unique IP Addresses: {analysis_summary['unique_ips']}\n")
                file.write(f"Suspicious IPs Detected: {len(analysis_summary['suspicious_ips'])}\n")
                file.write(f"Off-Hours Access Attempts: {len(analysis_summary['off_hours_access'])}\n\n")
                
                # Alert Summary
                file.write("ALERT SUMMARY\n")
                file.write("-"*80 + "\n")
                total_alerts = sum(alert_summary.values())
                file.write(f"Total Alerts Generated: {total_alerts}\n")
                file.write(f"  • CRITICAL: {alert_summary['CRITICAL']}\n")
                file.write(f"  • HIGH: {alert_summary['HIGH']}\n")
                file.write(f"  • MEDIUM: {alert_summary['MEDIUM']}\n")
                file.write(f"  • LOW: {alert_summary['LOW']}\n\n")
                
                # Failed Login Analysis
                file.write("FAILED LOGIN ANALYSIS\n")
                file.write("-"*80 + "\n")
                
                if analysis_summary['failed_logins']['by_user']:
                    file.write("Users with Repeated Failed Attempts:\n")
                    for user, count in sorted(analysis_summary['failed_logins']['by_user'].items(), 
                                             key=lambda x: x[1], reverse=True):
                        file.write(f"  • {user}: {count} failed attempts\n")
                else:
                    file.write("No users with repeated failed attempts detected.\n")
                
                file.write("\n")
                
                if analysis_summary['failed_logins']['by_ip']:
                    file.write("IPs with Repeated Failed Attempts:\n")
                    for ip, count in sorted(analysis_summary['failed_logins']['by_ip'].items(), 
                                           key=lambda x: x[1], reverse=True):
                        file.write(f"  • {ip}: {count} failed attempts\n")
                else:
                    file.write("No IPs with repeated failed attempts detected.\n")
                
                file.write("\n")
                
                # Suspicious IP Analysis
                file.write("SUSPICIOUS IP ANALYSIS\n")
                file.write("-"*80 + "\n")
                
                if analysis_summary['suspicious_ips']:
                    for ip, details in analysis_summary['suspicious_ips'].items():
                        file.write(f"\nIP Address: {ip}\n")
                        file.write(f"  • Failed Attempts: {details['failed_attempts']}\n")
                        file.write(f"  • Users Targeted: {', '.join(details['users_targeted'])}\n")
                        file.write(f"  • Total Users: {details['user_count']}\n")
                        
                        if details['first_seen']:
                            file.write(f"  • First Seen: {details['first_seen'].strftime('%Y-%m-%d %H:%M:%S')}\n")
                        if details['last_seen']:
                            file.write(f"  • Last Seen: {details['last_seen'].strftime('%Y-%m-%d %H:%M:%S')}\n")
                        
                        file.write(f"  • Risk Level: HIGH - Targeting multiple accounts\n")
                else:
                    file.write("No suspicious IP patterns detected.\n")
                
                file.write("\n")
                
                # Off-Hours Access Analysis
                file.write("OFF-HOURS ACCESS ANALYSIS\n")
                file.write("-"*80 + "\n")
                file.write("Off-Hours Period: 10:00 PM - 6:00 AM\n\n")
                
                if analysis_summary['off_hours_access']:
                    file.write(f"Total Off-Hours Attempts: {len(analysis_summary['off_hours_access'])}\n\n")
                    
                    # Group by IP
                    off_hours_by_ip = {}
                    for entry in analysis_summary['off_hours_access']:
                        ip = entry['ip']
                        if ip not in off_hours_by_ip:
                            off_hours_by_ip[ip] = []
                        off_hours_by_ip[ip].append(entry)
                    
                    file.write("IPs with Off-Hours Activity:\n")
                    for ip, entries in off_hours_by_ip.items():
                        failed_count = len([e for e in entries if e['action'] == 'LOGIN_FAILED'])
                        file.write(f"  • {ip}: {len(entries)} attempts ({failed_count} failed)\n")
                else:
                    file.write("No off-hours access attempts detected.\n")
                
                file.write("\n")
                
                # Security Recommendations
                file.write("SECURITY RECOMMENDATIONS\n")
                file.write("-"*80 + "\n")
                
                recommendations = []
                
                # Generate recommendations based on findings
                if alert_summary['CRITICAL'] > 0:
                    recommendations.append("🚨 IMMEDIATE ACTION REQUIRED:")
                    recommendations.append("   - Investigate all CRITICAL alerts immediately")
                    recommendations.append("   - Consider temporary account lockouts for affected users")
                    recommendations.append("   - Block suspicious IP addresses at firewall level")
                
                if len(analysis_summary['suspicious_ips']) > 0:
                    recommendations.append("⚠️  IP Security:")
                    recommendations.append("   - Implement IP-based rate limiting")
                    recommendations.append("   - Consider geo-blocking for high-risk regions")
                    recommendations.append("   - Enable CAPTCHA after 2 failed attempts")
                
                if len(analysis_summary['off_hours_access']) > 0:
                    recommendations.append("🌙 Off-Hours Security:")
                    recommendations.append("   - Require multi-factor authentication for off-hours access")
                    recommendations.append("   - Set up real-time alerts for off-hours login attempts")
                    recommendations.append("   - Review legitimate need for off-hours access")
                
                if analysis_summary['failed_logins']['total_failed'] > 10:
                    recommendations.append("🔐 Authentication Security:")
                    recommendations.append("   - Implement account lockout after 3 failed attempts")
                    recommendations.append("   - Enforce strong password policies")
                    recommendations.append("   - Consider implementing multi-factor authentication")
                
                recommendations.append("📊 General Best Practices:")
                recommendations.append("   - Regular security audits and log reviews")
                recommendations.append("   - Keep security monitoring systems up to date")
                recommendations.append("   - Train staff on security awareness")
                recommendations.append("   - Maintain incident response procedures")
                
                for recommendation in recommendations:
                    file.write(f"{recommendation}\n")
                
                file.write("\n")
                
                # Footer
                file.write("="*80 + "\n")
                file.write("END OF REPORT\n")
                file.write("="*80 + "\n")
            
            print(f"\n✓ Comprehensive report generated: {filepath}")
            return filepath
            
        except IOError as e:
            print(f"✗ Error generating report: {e}")
            return None
    
    def generate_quick_summary(self, analysis_summary):
        """
        Generate a quick summary for terminal display.
        
        Args:
            analysis_summary (dict): Results from LogAnalyzer
        """
        print("\n" + "="*80)
        print("QUICK SECURITY SUMMARY")
        print("="*80)
        
        # Calculate risk score (simple heuristic)
        risk_score = 0
        risk_score += len(analysis_summary['suspicious_ips']) * 10
        risk_score += analysis_summary['failed_logins']['total_failed'] * 2
        risk_score += len(analysis_summary['off_hours_access']) * 5
        
        # Determine risk level
        if risk_score >= 100:
            risk_level = "🔴 CRITICAL"
        elif risk_score >= 50:
            risk_level = "🟠 HIGH"
        elif risk_score >= 20:
            risk_level = "🟡 MEDIUM"
        else:
            risk_level = "🟢 LOW"
        
        print(f"Overall Risk Level: {risk_level} (Score: {risk_score})")
        print(f"Total Entries: {analysis_summary['total_entries']}")
        print(f"Failed Logins: {analysis_summary['failed_logins']['total_failed']}")
        print(f"Suspicious IPs: {len(analysis_summary['suspicious_ips'])}")
        print(f"Off-Hours Access: {len(analysis_summary['off_hours_access'])}")
        print("="*80 + "\n")


# Test function
if __name__ == "__main__":
    print("Report Generator module loaded successfully!")
    print("Import this module in main.py to use its functionality.")
