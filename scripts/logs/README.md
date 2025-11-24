# Sentinel Log Analyzer (SSH + sudo)

This folder contains the **log analyzer** part of the project.  
It reads auth-related system logs, turns them into structured events and runs detection rules on top.

Main goals:

- Spot **brute-force SSH attacks**
- Detect **risky root logins**
- Catch **sudo-spawned root shells**
- Correlate **SSH login → sudo root shell** as a possible privilege escalation chain

---

## 📁 Files

- **`sources.py`** – finds and reads log lines
  - Tries `/var/log/auth.log` (Debian/Ubuntu)
  - Tries `/var/log/secure` (RHEL/Fedora)
  - If log files are missing, falls back to `journalctl -n 1000`
- **`parser.py`** – parses raw lines into `LogEvent` objects
  - SSH auth events from `sshd`
  - sudo command events (e.g. `sudo bash` → root shell)
- **`results.py`** – data models & severities
  - `LogEvent`, `DetectionResult`, `LogAnalysisResult`
  - Severity constants:
    - `SEVERITY_LOW`
    - `SEVERITY_MEDIUM`
    - `SEVERITY_HIGH`
    - `SEVERITY_CRITICAL`
- **`detections.py`** – detection rules & rule config
  - `DETECTION_REGISTRY` – all registered rules
  - `DEFAULT_DETECTION_CONFIG` – default settings per rule
- **`log_analyzer.py`** – CLI entry point and public API
  - `analyze_logs(...)` – main function used by the rest of the project
  - Command-line interface for running the analyzer

---

## 🔍 What it detects

Each detection is represented as a `DetectionResult` with:

- rule **id**
- **severity**
- short **description**
- human-readable **evidence**
- list of related **events** (`LogEvent`)

Current rules:

- **`ssh_bruteforce`**
  - Many **failed** SSH logins from the same IP in a short time window
  - Localhost IPs → lower severity, remote IPs → higher severity
- **`ssh_root_login`**
  - Successful SSH logins as **root**
  - From localhost → medium severity  
  - From non-local IPs → high severity
- **`ssh_many_success`**
  - Many successful SSH logins from the same IP in a short window  
  - Can indicate scripts, automation or suspicious access patterns
- **`sudo_root_shell`**
  - `sudo` commands that spawn a **root shell**  
    (e.g. `sudo bash`, `sudo sh`, `sudo -i`, `sudo su`)
- **`ssh_sudo_root_chain`**
  - **Correlation rule**
  - SSH login for user *U* followed by a `sudo` root shell by the **same user U**
  - Within a configurable time window (default 10 minutes)

---

## ⚙️ How it works

1. **Read logs**

   `sources.read_auth_log()` collects raw lines from:

   - `/var/log/auth.log` or `/var/log/secure`, if they exist  
   - otherwise, the tail of the systemd journal (`journalctl -n 1000`)

2. **Parse into events**

   `parser.parse_all_events(lines)` converts raw strings into `LogEvent` objects:

   - `timestamp` – parsed from syslog-style timestamp
   - `source` – logical source (`"ssh"`, `"sudo"`, etc.)
   - `host`, `pid` – extracted from the log prefix
   - `fields` – structured data (status, user, ip, port, target_user, command, ...)

3. **Run detection rules**

   `log_analyzer.analyze_logs(...)`:

   - loads rule functions from `DETECTION_REGISTRY`
   - reads default config from `DEFAULT_DETECTION_CONFIG`
   - optionally filters which rules to run (`enabled_rules`)
   - returns a `LogAnalysisResult`:
     - `events` – all parsed events
     - `detections` – all rule hits

4. **Print results (CLI)**

   `log_analyzer.py` (when run as a script):

   - prints debug info (how many events, how many detections, events per source)
   - prints each detection with evidence and a few sample events

---

## 🖥️ CLI usage

From inside `scripts/logs/`:

```bash
# Analyze real system logs with all rules
doas python log_analyzer.py
# or
sudo python log_analyzer.py

