# 📊 Visual Architecture & Workflow Guide

## 🏗️ System Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────────┐
│                         SERVER LOG ANALYZER                         │
│                            (main.py)                                │
└────────────┬────────────────────────────────────────────────────────┘
             │
             ├─────────────────────────────────────────────────────────┐
             │                                                         │
             ▼                                                         │
┌────────────────────────┐                                            │
│   LOG FILES (.log)     │                                            │
│  ─────────────────     │                                            │
│  server_access.log     │                                            │
│  auth_log_jan2026.log  │                                            │
└───────────┬────────────┘                                            │
            │                                                          │
            │ reads                                                    │
            ▼                                                          │
┌────────────────────────┐                                            │
│     LOG READER         │                                            │
│   (log_reader.py)      │                                            │
│  ─────────────────     │                                            │
│  • Read files          │                                            │
│  • Parse with regex    │◄───────────── orchestrates ───────────────┘
│  • Extract data        │
└───────────┬────────────┘
            │
            │ parsed entries
            ▼
┌────────────────────────┐
│    LOG ANALYZER        │
│    (analyzer.py)       │
│  ─────────────────     │
│  • Detect patterns     │
│  • Count failures      │
│  • Find suspicious IPs │
│  • Check off-hours     │
└───────────┬────────────┘
            │
            │ analysis results
            ├─────────────────────┬──────────────────────┐
            │                     │                      │
            ▼                     ▼                      ▼
┌─────────────────────┐  ┌──────────────────┐  ┌─────────────────┐
│  ALERT MANAGER      │  │ REPORT GENERATOR │  │  TERMINAL       │
│ (alert_manager.py)  │  │(report_gen.py)   │  │  OUTPUT         │
│  ────────────────   │  │  ─────────────   │  │  ────────────   │
│  • Generate alerts  │  │  • Create report │  │  • Color-coded  │
│  • Classify severity│  │  • Add stats     │  │  • Real-time    │
│  • Display in term. │  │  • Recommend     │  │  • Interactive  │
└────────┬────────────┘  └────────┬─────────┘  └─────────────────┘
         │                        │
         │ saves                  │ saves
         ▼                        ▼
┌────────────────────────────────────────────┐
│        OUTPUT DIRECTORY                    │
│  ───────────────────────────────────────   │
│  📄 security_alerts.txt                    │
│  📄 security_report_YYYYMMDD_HHMMSS.txt   │
└────────────────────────────────────────────┘
```

---

## 🔄 Data Flow Diagram

```
Raw Log Text
     ↓
  ┌──────────────────────────────────────────────────────────┐
  │ "2026-02-10 08:20:12 | WARNING | User: admin |          │
  │  IP: 203.0.113.42 | Action: LOGIN_FAILED | Status: 401" │
  └──────────────────────────────────────────────────────────┘
     ↓ (regex parsing)
  ┌──────────────────────────────────────────────────────────┐
  │ {                                                         │
  │   'timestamp': datetime(2026, 2, 10, 8, 20, 12),        │
  │   'level': 'WARNING',                                    │
  │   'user': 'admin',                                       │
  │   'ip': '203.0.113.42',                                  │
  │   'action': 'LOGIN_FAILED',                              │
  │   'status': 401                                          │
  │ }                                                         │
  └──────────────────────────────────────────────────────────┘
     ↓ (pattern analysis)
  ┌──────────────────────────────────────────────────────────┐
  │ Analysis Results:                                         │
  │ • IP '203.0.113.42': 4 failed attempts                   │
  │ • User 'admin': 4 failed attempts                        │
  │ • Risk Level: HIGH                                       │
  └──────────────────────────────────────────────────────────┘
     ↓ (alert generation)
  ┌──────────────────────────────────────────────────────────┐
  │ 🚨 CRITICAL ALERT                                        │
  │ IP '203.0.113.42' shows brute force pattern              │
  │ Recommendation: Block IP immediately                     │
  └──────────────────────────────────────────────────────────┘
```

---

## ⚙️ Module Interaction Flow

```
┌─────────────────────────────────────────────────────────────────┐
│                          main.py                                │
│  ─────────────────────────────────────────────────────────────  │
│                                                                 │
│  1. Initialize                                                  │
│     ├─ Create AlertManager                                     │
│     └─ Create ReportGenerator                                  │
│                                                                 │
│  2. For each log file:                                         │
│     ├─ LogReader.read_logs()        ───────────────┐          │
│     ├─ LogReader.parse_all_logs()                   │          │
│     │                                                │          │
│     ├─ LogAnalyzer(parsed_entries)   <──────────────┘          │
│     ├─ LogAnalyzer.detect_failed_logins()                      │
│     ├─ LogAnalyzer.detect_suspicious_ips()                     │
│     ├─ LogAnalyzer.detect_off_hours_access()                   │
│     │                                                │          │
│     ├─ AlertManager.generate_alerts() <─────────────┘          │
│     └─ ReportGenerator.generate_summary()                      │
│                                                                 │
│  3. Save outputs                                               │
│     ├─ AlertManager.save_alerts_to_file()                      │
│     └─ ReportGenerator.generate_summary_report()               │
└─────────────────────────────────────────────────────────────────┘
```

---

## 🎯 Detection Algorithm Flowcharts

### A) Failed Login Detection

```
START
  ↓
Filter entries where
action == 'LOGIN_FAILED'
  ↓
Count by IP using Counter
Count by User using Counter
  ↓
Are counts >= threshold (3)?
  ├─ YES → Add to suspicious list
  │         ↓
  │         Classify severity:
  │         • 3-4 attempts = HIGH
  │         • 5+ attempts = CRITICAL
  │         ↓
  │         Generate Alert
  │
  └─ NO → Skip (legitimate failure)
  ↓
END
```

### B) Suspicious IP Detection

```
START
  ↓
For each log entry:
  ↓
Create IP activity map with:
  • failed_attempts counter
  • users_targeted set
  • timestamps list
  ↓
For each IP in map:
  ↓
Is failed_attempts >= 3
OR users_targeted >= 2?
  ├─ YES → Flag as suspicious
  │         ↓
  │         Calculate risk:
  │         • Multiple users = CRITICAL
  │         • High attempts = HIGH
  │         ↓
  │         Generate Alert
  │
  └─ NO → Mark as normal activity
  ↓
END
```

### C) Off-Hours Detection

```
START
  ↓
For each log entry:
  ↓
Extract timestamp
  ↓
Is time between
22:00 and 06:00?
  ├─ YES → Is action == 'LOGIN_FAILED'?
  │         ├─ YES → Add to off-hours threats
  │         │         ↓
  │         │         Severity = CRITICAL
  │         │         (off-hours + failed = high risk)
  │         │         ↓
  │         │         Generate Alert
  │         │
  │         └─ NO → Log but lower priority
  │
  └─ NO → Normal business hours
  ↓
END
```

---

## 📈 Data Structure Usage

### 1. Counter (from collections)
```python
# Example: Count failed attempts by IP
from collections import Counter

failed_by_ip = Counter(['192.168.1.1', '192.168.1.1', '203.0.113.42'])
# Result: Counter({'192.168.1.1': 2, '203.0.113.42': 1})

# Efficient O(n) counting instead of O(n²) loops
```

### 2. defaultdict (from collections)
```python
# Example: Track IP activity
from collections import defaultdict

ip_activity = defaultdict(lambda: {
    'failed_attempts': 0,
    'users_targeted': set(),
    'timestamps': []
})

ip_activity['203.0.113.42']['failed_attempts'] += 1
ip_activity['203.0.113.42']['users_targeted'].add('admin')
# Automatically creates nested structure
```

### 3. Sets for Unique Tracking
```python
# Example: Track unique users targeted by an IP
users_targeted = set()
users_targeted.add('admin')
users_targeted.add('root')
users_targeted.add('admin')  # Duplicate ignored
# Result: {'admin', 'root'} - only 2 unique users
```

---

## 🎨 Alert Severity Classification

```
┌──────────────────────────────────────────────────────────────┐
│                    SEVERITY MATRIX                           │
├──────────────┬───────────────────────────────────────────────┤
│   CRITICAL   │ • 5+ failed attempts from single IP/user     │
│     🚨       │ • IP targeting 3+ different accounts         │
│              │ • Off-hours access with failed attempts      │
│              │ → Immediate action required                  │
├──────────────┼───────────────────────────────────────────────┤
│     HIGH     │ • 3-4 failed attempts from single IP/user    │
│     ⚠️       │ • IP targeting 2 different accounts          │
│              │ • Off-hours successful logins                │
│              │ → Investigation recommended                  │
├──────────────┼───────────────────────────────────────────────┤
│    MEDIUM    │ • 2 failed attempts                          │
│     ⚡       │ • Known IP with unusual pattern              │
│              │ → Monitor closely                            │
├──────────────┼───────────────────────────────────────────────┤
│     LOW      │ • Single failed attempt                      │
│     ℹ️       │ • Informational only                         │
│              │ → Log for reference                          │
└──────────────┴───────────────────────────────────────────────┘
```

---

## 🔍 Regex Pattern Breakdown

```
Pattern: r'(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})\s*\|\s*(\w+)\s*\|...'

Breaking it down:

┌─────────────────────────────────────────────────────────────┐
│ Sample Input:                                               │
│ "2026-02-10 08:20:12 | WARNING | User: admin | ..."       │
└─────────────────────────────────────────────────────────────┘
       │
       ├─ (\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})
       │  └─ Matches: "2026-02-10 08:20:12"
       │     • \d{4} = 4 digits (year)
       │     • \d{2} = 2 digits (month, day, hour, minute, second)
       │     • \s+ = one or more spaces
       │
       ├─ \s*\|\s*
       │  └─ Matches: " | " (flexible whitespace around pipe)
       │
       ├─ (\w+)
       │  └─ Matches: "WARNING" (word characters)
       │
       ├─ User:\s*(\S+)
       │  └─ Matches: "User: admin"
       │     • \S+ = non-whitespace characters (username)
       │
       ├─ IP:\s*([\d.]+)
       │  └─ Matches: "IP: 203.0.113.42"
       │     • [\d.]+ = digits and dots (IP address)
       │
       └─ Status:\s*(\d+)
          └─ Matches: "Status: 401"
             • \d+ = one or more digits (status code)
```

---

## 📊 Performance Characteristics

```
┌──────────────────────────────────────────────────────────┐
│              Time Complexity Analysis                    │
├────────────────────────┬─────────────────────────────────┤
│ Operation              │ Complexity  │ Why?             │
├────────────────────────┼─────────────────────────────────┤
│ Read log file          │ O(n)        │ Sequential read  │
│ Parse with regex       │ O(n)        │ One pass         │
│ Failed login detection │ O(n)        │ Counter is O(n)  │
│ Suspicious IP analysis │ O(n)        │ Single iteration │
│ Off-hours detection    │ O(n)        │ Single iteration │
├────────────────────────┼─────────────────────────────────┤
│ OVERALL                │ O(n)        │ Linear scaling   │
└────────────────────────┴─────────────────────────────────┘

Space Complexity: O(n) - stores all parsed entries in memory

For 10,000 log entries: ~1-2 seconds processing time
```

---

## 🎯 Quick Reference: "What Does Each Module Do?"

```
╔══════════════════════════════════════════════════════════════╗
║  MODULE           │  RESPONSIBILITY                          ║
╠══════════════════════════════════════════════════════════════╣
║  log_reader.py    │  Reads files, parses with regex         ║
║                   │  Returns: List of dictionaries          ║
╠═══════════════════┼══════════════════════════════════════════╣
║  analyzer.py      │  Detects security patterns              ║
║                   │  Returns: Analysis summary dict         ║
╠═══════════════════┼══════════════════════════════════════════╣
║  alert_manager.py │  Generates & displays alerts            ║
║                   │  Outputs: Terminal + alerts.txt         ║
╠═══════════════════┼══════════════════════════════════════════╣
║  report_gen.py    │  Creates detailed reports               ║
║                   │  Outputs: security_report_*.txt         ║
╠═══════════════════┼══════════════════════════════════════════╣
║  main.py          │  Orchestrates everything                ║
║                   │  Coordinates: All modules               ║
╚══════════════════════════════════════════════════════════════╝
```

---

## 💡 Interview Presentation Tips

### How to Draw This on a Whiteboard

1. **Start with boxes**: Draw 5 rectangles for modules
2. **Add arrows**: Show data flow between modules
3. **Label clearly**: Write module names and purposes
4. **Add example data**: Show sample input/output
5. **Explain as you draw**: "First, we read the logs..."

### What to Emphasize

✅ **Modular design** - Each component has one job
✅ **Data transformation** - Raw text → Structured data → Insights
✅ **Efficient algorithms** - O(n) complexity using Counter
✅ **Professional output** - Not just console prints
✅ **Real-world application** - Solves actual security problems

---

## 🎓 Study This Before Interview

**memorize:**
1. The data flow (raw → parsed → analyzed → alerted)
2. Three detection algorithms and thresholds
3. Why you chose each Python module
4. Time complexity (O(n)) and why

**Practice drawing:**
- Architecture diagram (5 boxes + arrows)
- Data structure examples (Counter, defaultdict)

**Be ready to explain:**
- Any line of code from your project
- Design decisions (why modular? why these thresholds?)
- How you'd scale it for production

---

## ✅ Final Preparation Checklist

⬜ Can you draw the architecture from memory?
⬜ Can you explain the regex pattern?
⬜ Can you describe each algorithm's logic?
⬜ Do you know the time complexity?
⬜ Can you name all 5 modules and their purposes?
⬜ Have you practiced your 30-second pitch?
⬜ Can you discuss improvements you'd make?

---

**You're ready to ace that interview! 🚀**
