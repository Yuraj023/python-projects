"""
main.py
-------
Main entry point for the Server Log Analyzer application.
Orchestrates all modules to analyze server logs and generate security reports.

Author: [Your Name]
Project: Server Log Security Analyzer
"""

import os
import sys
from datetime import datetime

# Import custom modules
from log_reader import LogReader
from analyzer import LogAnalyzer
from alert_manager import AlertManager
from report_generator import ReportGenerator


def print_banner():
    """Display application banner."""
    banner = """
    ╔════════════════════════════════════════════════════════════════╗
    ║                                                                ║
    ║           SERVER LOG SECURITY ANALYZER v1.0                    ║
    ║           Automated Security Threat Detection                  ║
    ║                                                                ║
    ╚════════════════════════════════════════════════════════════════╝
    """
    print(banner)


def get_log_files(log_directory):
    """
    Get all .log files from the specified directory.
    
    Args:
        log_directory (str): Path to log directory
        
    Returns:
        list: List of log file paths
    """
    try:
        if not os.path.exists(log_directory):
            print(f"✗ Error: Log directory not found: {log_directory}")
            return []
        
        # Find all .log files
        log_files = [os.path.join(log_directory, f) 
                    for f in os.listdir(log_directory) 
                    if f.endswith('.log')]
        
        if not log_files:
            print(f"✗ No log files found in {log_directory}")
            return []
        
        print(f"✓ Found {len(log_files)} log file(s) to analyze")
        return log_files
        
    except Exception as e:
        print(f"✗ Error scanning log directory: {e}")
        return []


def analyze_single_log(log_file_path, alert_manager, report_generator):
    """
    Analyze a single log file.
    
    Args:
        log_file_path (str): Path to log file
        alert_manager (AlertManager): Alert manager instance
        report_generator (ReportGenerator): Report generator instance
        
    Returns:
        dict: Analysis summary
    """
    print(f"\n{'='*80}")
    print(f"Analyzing: {os.path.basename(log_file_path)}")
    print(f"{'='*80}")
    
    # Step 1: Read and parse logs
    print("\n[1/4] Reading and parsing log file...")
    log_reader = LogReader(log_file_path)
    
    try:
        parsed_entries = log_reader.parse_all_logs()
        
        if not parsed_entries:
            print("✗ No valid log entries found")
            return None
        
    except Exception as e:
        print(f"✗ Error reading log file: {e}")
        return None
    
    # Step 2: Analyze logs for security threats
    print("\n[2/4] Analyzing logs for security threats...")
    analyzer = LogAnalyzer(parsed_entries)
    analysis_summary = analyzer.generate_security_summary()
    
    # Step 3: Generate alerts
    print("\n[3/4] Generating security alerts...")
    
    # Generate failed login alerts
    if analysis_summary['failed_logins']['by_user'] or analysis_summary['failed_logins']['by_ip']:
        alert_manager.generate_failed_login_alerts(analysis_summary['failed_logins'])
    
    # Generate suspicious IP alerts
    if analysis_summary['suspicious_ips']:
        alert_manager.generate_suspicious_ip_alerts(analysis_summary['suspicious_ips'])
    
    # Generate off-hours alerts
    if analysis_summary['off_hours_access']:
        alert_manager.generate_off_hours_alerts(analysis_summary['off_hours_access'])
    
    # Step 4: Display quick summary
    print("\n[4/4] Generating report summary...")
    report_generator.generate_quick_summary(analysis_summary)
    
    return analysis_summary


def main():
    """Main application function."""
    try:
        # Display banner
        print_banner()
        print(f"Analysis started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        
        # Setup paths
        current_dir = os.path.dirname(os.path.abspath(__file__))
        log_directory = os.path.join(current_dir, "..", "logs")
        output_directory = os.path.join(current_dir, "..", "output")
        
        # Normalize paths
        log_directory = os.path.normpath(log_directory)
        output_directory = os.path.normpath(output_directory)
        
        print(f"Log Directory: {log_directory}")
        print(f"Output Directory: {output_directory}\n")
        
        # Get all log files
        log_files = get_log_files(log_directory)
        
        if not log_files:
            print("\n✗ No log files to analyze. Exiting.")
            return
        
        # Initialize managers
        alert_manager = AlertManager(output_directory)
        report_generator = ReportGenerator(output_directory)
        
        # Analyze each log file
        all_summaries = []
        
        for log_file in log_files:
            summary = analyze_single_log(log_file, alert_manager, report_generator)
            if summary:
                all_summaries.append(summary)
        
        # Generate final reports
        if all_summaries:
            print("\n" + "="*80)
            print("GENERATING FINAL REPORTS")
            print("="*80)
            
            # Combine summaries for comprehensive report
            combined_summary = all_summaries[0] if len(all_summaries) == 1 else {
                'total_entries': sum(s['total_entries'] for s in all_summaries),
                'successful_logins': sum(s['successful_logins'] for s in all_summaries),
                'failed_logins': {
                    'total_failed': sum(s['failed_logins']['total_failed'] for s in all_summaries),
                    'by_user': {},
                    'by_ip': {}
                },
                'suspicious_ips': {},
                'off_hours_access': [],
                'unique_users': 0,
                'unique_ips': 0
            }
            
            # Get alert summary
            alert_summary = alert_manager.get_alert_summary()
            
            # Save alerts to file
            alert_manager.save_alerts_to_file()
            
            # Generate comprehensive report
            report_generator.generate_summary_report(combined_summary, alert_summary)
            
            # Final summary
            print("\n" + "="*80)
            print("ANALYSIS COMPLETE")
            print("="*80)
            print(f"✓ Analyzed {len(log_files)} log file(s)")
            print(f"✓ Generated {len(alert_manager.alerts)} security alert(s)")
            print(f"✓ Reports saved to: {output_directory}")
            print("\nAlert Breakdown:")
            print(f"  🚨 CRITICAL: {alert_summary['CRITICAL']}")
            print(f"  ⚠️  HIGH: {alert_summary['HIGH']}")
            print(f"  ⚡ MEDIUM: {alert_summary['MEDIUM']}")
            print(f"  ℹ️  LOW: {alert_summary['LOW']}")
            print("="*80)
            
        else:
            print("\n✗ No summaries generated. Check log files and try again.")
        
        print(f"\nAnalysis completed at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        
    except KeyboardInterrupt:
        print("\n\n✗ Analysis interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n✗ Unexpected error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
