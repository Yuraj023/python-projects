### 🔐 Server Log Security Analyzer
A professional Python application that analyzes server log files to detect security threats, identify suspicious activities, and generate comprehensive security reports. Perfect for demonstrating cybersecurity and data analysis skills.

## 🎯 Project Overview

This project automates the analysis of server access logs to identify:
- **Failed Login Attempts**: Detects brute force attacks and credential stuffing
- **Suspicious IP Addresses**: Identifies IPs targeting multiple user accounts
- **Off-Hours Access**: Flags login attempts during suspicious hours (10 PM - 6 AM)
- **Security Patterns**: Analyzes trends and generates actionable alerts

## ✨ Features

✅ **Modular Architecture**: Clean separation of concerns with dedicated modules  
✅ **Regular Expression Parsing**: Efficient log parsing using Python's `re` module  
✅ **Data Structure Optimization**: Uses dictionaries, sets, and Counter for fast analysis  
✅ **Real-Time Alerts**: Color-coded terminal alerts with severity levels  
✅ **Comprehensive Reports**: Automated generation of detailed security reports  
✅ **Error Handling**: Robust exception handling for production-ready code  
✅ **Professional Output**: Well-formatted alerts and reports saved to files  

## 📁 Project Structure

```
server-log-analyzer/
│
├── src/                          # Source code
│   ├── main.py                   # Entry point & orchestration
│   ├── log_reader.py             # Log file reading & parsing
│   ├── analyzer.py               # Security threat analysis
│   ├── alert_manager.py          # Alert generation & display
│   └── report_generator.py       # Report creation
│
├── logs/                         # Sample log files
│   ├── server_access.log
│   └── auth_log_jan2026.log
│
├── output/                       # Generated reports & alerts
│   ├── security_alerts.txt
│   └── security_report_*.txt
│
├── docs/                         # Documentation
│   ├── RESUME_DESCRIPTION.md
│   └── INTERVIEW_GUIDE.md
│
├── .gitignore                    # Git ignore rules
└── README.md                     # This file
```

## 🚀 Getting Started

### Prerequisites

- Python 3.7 or higher
- No external dependencies required (uses Python standard library)

### Installation

1. **Clone the repository**
   ```bash
   git clone https://github.com/yourusername/server-log-analyzer.git
   cd server-log-analyzer
   ```

2. **Navigate to source directory**
   ```bash
   cd src
   ```

3. **Run the analyzer**
   ```bash
   python main.py
   ```

## 💻 Usage

### Basic Usage

Simply run the main script from the `src` directory:

```bash
python main.py
```

The application will:
1. Scan the `logs/` directory for `.log` files
2. Parse and analyze each log file
3. Generate color-coded security alerts in the terminal
4. Save detailed reports to the `output/` directory

### Sample Output

```
╔════════════════════════════════════════════════════════════════╗
║           SERVER LOG SECURITY ANALYZER v1.0                    ║
║           Automated Security Threat Detection                  ║
╚════════════════════════════════════════════════════════════════╝

✓ Found 2 log file(s) to analyze
✓ Successfully read 29 log entries from server_access.log
✓ Successfully parsed 29 log entries

🚨 SECURITY ALERT - CRITICAL
IP '203.0.113.42' has 4 failed login attempts
Recommendation: Consider IP blocking or rate limiting
```

## 🔧 Technical Implementation

### Key Technologies & Concepts

- **File Handling**: Uses `with` context managers for safe file operations
- **Regular Expressions**: Pattern matching with Python's `re` module
- **Collections Module**: Efficient data analysis with `Counter` and `defaultdict`
- **Object-Oriented Design**: Modular classes with single responsibilities
- **Error Handling**: Try-except blocks for robust error management
- **DateTime Operations**: Time-based analysis for off-hours detection

### Module Breakdown

#### 1. log_reader.py
- Reads log files and handles file I/O errors
- Uses regex to parse structured log data
- Extracts: timestamp, user, IP, action, status
- Provides filtering methods (by IP, user, action)

#### 2. analyzer.py
- Implements security analysis algorithms
- Uses `Counter` for frequency analysis
- Detects patterns: failed logins, suspicious IPs, off-hours access
- Calculates risk scores and threat levels

#### 3. alert_manager.py
- Generates severity-based alerts (CRITICAL, HIGH, MEDIUM, LOW)
- Uses ANSI color codes for terminal formatting
- Creates and saves alert logs
- Provides alert summaries and statistics

#### 4. report_generator.py
- Creates comprehensive security reports
- Generates executive summaries
- Provides actionable security recommendations
- Formats professional text reports with statistics

#### 5. main.py
- Orchestrates all modules
- Handles command-line execution
- Manages workflow and error handling
- Displays professional banners and summaries

## 📊 Sample Analysis Results

The analyzer processes logs and generates:

### Threats Detected (Example)
- 🚨 **4 Suspicious IPs** with brute force patterns
- ⚠️ **12 Failed Login Attempts** from single IP
- 🌙 **8 Off-Hours Access Attempts** requiring investigation
- 🔐 **3 User Accounts** targeted by attackers

### Generated Files
- `security_alerts.txt` - All alerts with details
- `security_report_YYYYMMDD_HHMMSS.txt` - Comprehensive analysis report

## 🎓 Learning Outcomes

This project demonstrates proficiency in:

✅ Python fundamentals (file I/O, data structures, functions)  
✅ Regular expression pattern matching  
✅ Object-oriented programming principles  
✅ Security concepts (authentication, threat detection)  
✅ Data analysis and statistical processing  
✅ Professional code organization and documentation  
✅ Error handling and defensive programming  

## 🔒 Security Concepts Demonstrated

- **Brute Force Detection**: Identifying repeated failed login attempts
- **Credential Stuffing**: Detecting IPs trying multiple accounts
- **Anomaly Detection**: Flagging off-hours access patterns
- **Threat Intelligence**: IP reputation analysis
- **Incident Response**: Automated alert generation

## 🛠️ Future Enhancements

Potential features to add:
- [ ] IPv6 address support
- [ ] Machine learning for anomaly detection
- [ ] Email/SMS alert integration
- [ ] Dashboard with data visualization
- [ ] Database storage for historical analysis
- [ ] Real-time log monitoring
- [ ] Integration with SIEM systems



## 🤝 Contributing

Contributions, issues, and feature requests are welcome!

## ⭐ Show your support

Give a ⭐️ if this project helped you learn or demonstrate your Python skills!

---

**Note**: This is a demonstration project with sample log files. In production environments, ensure compliance with data privacy regulations and security policies when analyzing real server logs.
