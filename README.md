# DangerScope: Mini SOC Detection Pipeline

## Overview
DangerScope is a Python-based security log analysis tool that parses web server logs, detects suspicious activity, scores risk by IP address, and exports reports for review.

## Why I Built This
I built this project to gain hands-on experience with defensive cybersecurity, log analysis, detection engineering, and incident-style reporting.

## Features
- Parses Apache-style web server logs
- Detects repeated failed login attempts
- Flags admin route probing
- Detects SQL injection-like request patterns
- Detects path traversal attempts
- Identifies repeated 404 scanning behavior
- Scores suspicious IPs by risk level
- Exports JSON, CSV, and text reports
- Includes unit tests for parser and detector logic
- Optional Streamlit dashboard

## Detection Rules
| Detection | Description | Severity |
|---|---|---|
| Possible Brute Force | 5+ failed login attempts from same IP | High |
| SQL Injection Pattern | Request path contains SQL injection-like strings | High |
| Path Traversal | Request path contains ../ or /etc/passwd | High |
| Admin Route Probing | Request path targets admin-style pages | Medium |
| Repeated 404 Scanning | 5+ 404 responses from same IP | Medium |

## Example Output
Include screenshots or sample report output.

## What I Learned
- How web server logs are structured
- How suspicious behavior can be detected through patterns
- How false positives can happen in rule-based detection
- How to prioritize alerts using risk scoring
- How to document security findings clearly

## Limitations
- Rule-based detection can miss unknown attack patterns
- Sample logs are simplified compared to production logs
- IP-based scoring can create false positives with shared networks
- The tool does not currently use threat intelligence feeds

## Future Improvements
- Add support for multiple log formats
- Add GeoIP lookup
- Add IP reputation lookup
- Add MITRE ATT&CK mapping
- Add timeline visualization
- Add email or Slack alerts

## Security References
- OWASP Security Logging and Monitoring Failures
- OWASP Logging Cheat Sheet
- MITRE ATT&CK Brute Force T1110

## False Positive Considerations
A repeated 404 rule may flag vulnerability scanners, broken links, search engine crawlers, or users typing incorrect URLs. For that reason, DangerScope assigns repeated 404 behavior a medium severity instead of high severity.