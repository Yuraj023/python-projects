"""
log_reader.py
-------------
This module handles reading and parsing server log files.
It extracts structured data from raw log entries using regular expressions.
"""

import re
import os
from datetime import datetime


class LogReader:
    """
    Reads and parses server log files.
    Extracts timestamp, user, IP, action, and status from each log entry.
    """
    
    def __init__(self, log_file_path):
        """
        Initialize the LogReader with a file path.
        
        Args:
            log_file_path (str): Path to the log file
        """
        self.log_file_path = log_file_path
        self.log_entries = []
        
    def read_logs(self):
        """
        Read the log file and return raw content.
        
        Returns:
            list: List of raw log lines
            
        Raises:
            FileNotFoundError: If log file doesn't exist
            IOError: If file cannot be read
        """
        try:
            # Check if file exists
            if not os.path.exists(self.log_file_path):
                raise FileNotFoundError(f"Log file not found: {self.log_file_path}")
            
            # Read file content
            with open(self.log_file_path, 'r', encoding='utf-8') as file:
                lines = file.readlines()
                
            print(f"✓ Successfully read {len(lines)} log entries from {os.path.basename(self.log_file_path)}")
            return lines
            
        except FileNotFoundError as e:
            print(f"✗ Error: {e}")
            raise
        except IOError as e:
            print(f"✗ Error reading file: {e}")
            raise
        except Exception as e:
            print(f"✗ Unexpected error: {e}")
            raise
    
    def parse_log_line(self, line):
        """
        Parse a single log line and extract key information.
        
        Log format expected:
        YYYY-MM-DD HH:MM:SS | LEVEL | User: username | IP: x.x.x.x | Action: ACTION | Status: code
        
        Args:
            line (str): Single log line
            
        Returns:
            dict: Parsed log entry with keys: timestamp, level, user, ip, action, status
            None: If line cannot be parsed
        """
        # Regular expression pattern to match log format
        pattern = r'(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})\s*\|\s*(\w+)\s*\|\s*User:\s*(\S+)\s*\|\s*IP:\s*([\d.]+)\s*\|\s*Action:\s*(\w+)\s*\|\s*Status:\s*(\d+)'
        
        match = re.match(pattern, line)
        
        if match:
            # Extract matched groups
            timestamp_str, level, user, ip, action, status = match.groups()
            
            # Parse timestamp
            try:
                timestamp = datetime.strptime(timestamp_str, '%Y-%m-%d %H:%M:%S')
            except ValueError:
                timestamp = None
            
            # Return structured dictionary
            return {
                'timestamp': timestamp,
                'level': level,
                'user': user,
                'ip': ip,
                'action': action,
                'status': int(status),
                'raw_line': line.strip()
            }
        
        return None
    
    def parse_all_logs(self):
        """
        Read and parse all log entries from the file.
        
        Returns:
            list: List of parsed log entry dictionaries
        """
        raw_lines = self.read_logs()
        parsed_entries = []
        
        for line in raw_lines:
            parsed_entry = self.parse_log_line(line)
            if parsed_entry:
                parsed_entries.append(parsed_entry)
        
        self.log_entries = parsed_entries
        print(f"✓ Successfully parsed {len(parsed_entries)} log entries")
        
        return parsed_entries
    
    def get_entries_by_action(self, action):
        """
        Filter log entries by action type.
        
        Args:
            action (str): Action type (e.g., 'LOGIN_FAILED', 'LOGIN_SUCCESS')
            
        Returns:
            list: Filtered log entries
        """
        return [entry for entry in self.log_entries if entry['action'] == action]
    
    def get_entries_by_ip(self, ip_address):
        """
        Filter log entries by IP address.
        
        Args:
            ip_address (str): IP address to filter
            
        Returns:
            list: Filtered log entries
        """
        return [entry for entry in self.log_entries if entry['ip'] == ip_address]
    
    def get_entries_by_user(self, username):
        """
        Filter log entries by username.
        
        Args:
            username (str): Username to filter
            
        Returns:
            list: Filtered log entries
        """
        return [entry for entry in self.log_entries if entry['user'] == username]


# Test function (run only when this file is executed directly)
if __name__ == "__main__":
    # Example usage
    reader = LogReader("../logs/server_access.log")
    entries = reader.parse_all_logs()
    
    print("\n--- Sample Entries ---")
    for entry in entries[:3]:
        print(entry)
