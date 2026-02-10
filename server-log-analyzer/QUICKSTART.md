# Quick Start Guide

## 🚀 How to Run This Project

### Step 1: Verify Python Installation
```bash
python --version
```
Make sure you have Python 3.7 or higher.

### Step 2: Navigate to Project Directory
```bash
cd server-log-analyzer/src
```

### Step 3: Run the Analyzer
```bash
python main.py
```

### Step 4: View Results
- **Terminal**: See color-coded alerts in real-time
- **Output Folder**: Check `../output/` for:
  - `security_alerts.txt` - All generated alerts
  - `security_report_*.txt` - Comprehensive analysis report

---

## 📝 Adding Your Own Log Files

1. Place your `.log` files in the `logs/` directory
2. Ensure logs follow the format:
   ```
   YYYY-MM-DD HH:MM:SS | LEVEL | User: username | IP: x.x.x.x | Action: ACTION | Status: code
   ```
3. Run the analyzer—it will automatically detect and process all `.log` files

---

## 🎯 Testing Different Scenarios

### Test Failed Login Detection
Look for entries in sample logs with `LOGIN_FAILED` action and count >= 3

### Test Off-Hours Detection
Check logs between 10 PM (22:00) and 6 AM (06:00)

### Test Suspicious IP Detection
Find IPs that target multiple different usernames

---

## 💡 Understanding the Output

### Alert Severity Levels:
- 🚨 **CRITICAL** - Immediate action required (5+ failed attempts)
- ⚠️ **HIGH** - Serious threat (3-4 failed attempts)
- ⚡ **MEDIUM** - Potential concern (2 failed attempts, multiple users)
- ℹ️ **LOW** - Informational (worth monitoring)

---

## 🔧 Customization

To change detection thresholds, edit these values in `analyzer.py`:
```python
self.failed_login_threshold = 3  # Number of failures to trigger alert
self.off_hours_start = time(22, 0)  # 10 PM
self.off_hours_end = time(6, 0)    # 6 AM
```

---

## ❓ Troubleshooting

**Issue**: "No log files found"
- **Solution**: Make sure `.log` files are in the `logs/` directory

**Issue**: "No valid log entries found"
- **Solution**: Check log format matches expected pattern (see regex in log_reader.py)

**Issue**: "Permission denied" when saving reports
- **Solution**: Ensure `output/` directory has write permissions

---

## 📊 Sample Output

```
╔════════════════════════════════════════════════════════════════╗
║           SERVER LOG SECURITY ANALYZER v1.0                    ║
╚════════════════════════════════════════════════════════════════╝

✓ Found 2 log file(s) to analyze
✓ Successfully read 29 log entries from server_access.log
✓ Successfully parsed 29 log entries
✓ Detected 2 users with repeated failed logins
✓ Detected 3 suspicious IPs with failed attempts

🚨 SECURITY ALERT - CRITICAL
IP '203.0.113.42' has 4 failed login attempts
Recommendation: Consider IP blocking or rate limiting

✓ Alerts saved to: output/security_alerts.txt
✓ Report generated: output/security_report_20260210_143022.txt
```

---

## 🎓 Next Steps

1. **Review Generated Reports**: Open files in `output/` directory
2. **Analyze Different Logs**: Add your own log files to test
3. **Customize Thresholds**: Adjust detection sensitivity
4. **Enhance Features**: Add email alerts, database storage, etc.
5. **Share on GitHub**: Push to your repository and showcase it!

---

**Need help?** Check the [Interview Guide](docs/INTERVIEW_GUIDE.md) for technical explanations!
