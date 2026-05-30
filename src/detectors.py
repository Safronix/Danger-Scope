from collections import defaultdict

ADMIN_PATHS = {
    "/admin",
    "/administrator",
    "/wp-admin",
    "/phpmyadmin",
}

SQLI_PATTERNS = [
    "' or 1=1",
    '" or 1=1,'
    "union select",
    "--",
    "select ",
    "drop table",
]

PATH_TRAVERSAL_PATTERNS = [
    "../",
    "..\\",
    "%2e%2e%2f",
    "%2e%2e\\",
    "/etc/passwd",
]

def detect_admin_probing(entries):
    alerts = []

    for entry in entries:
        path = entry["path"].lower()

        if any(admin_path in path for admin_path in ADMIN_PATHS):
            alerts.append({
                "ip": entry["ip"],
                "type": "Admin Route Probing",
                "severity": "medium",
                "description": f"Requested suspicious admin path: {entry['path']}",
                "entry": entry
            })
    return alerts

def detect_sql_injection_patterns(entries):
    alerts = []

    for entry in entries:
        path = entry["path"].lower()

        if any(pattern in path for pattern in SQLI_PATTERNS):
            alerts.append({
                "ip": entry["ip"],
                "type": "Possible SQL Injection",
                "severity": "high",
                "description": f"Request path contains SQL injection-like pattern: {entry['path']}",
                "entry": entry
            })

    return alerts


def detect_path_traversal(entries):
    alerts = []

    for entry in entries:
        path = entry["path"].lower()

        if any(pattern in path for pattern in PATH_TRAVERSAL_PATTERNS):
            alerts.append({
                "ip": entry["ip"],
                "type": "Possible Path Traversal",
                "severity": "high",
                "description": f"Request path contains path traversal pattern: {entry['path']}",
                "entry": entry
            })

    return alerts

def detect_brute_force(entries, threshold=5):
    failed_logins_by_ip = defaultdict(list)

    for entry in entries:
        path = entry["path"].lower()

        if "/login" in path and entry["status"] == 401:
            failed_logins_by_ip[entry["ip"]].append(entry)

    alerts = []

    for ip, failures in failed_logins_by_ip.items():
        if len(failures) >= threshold:
            alerts.append({
                "ip": ip,
                "type": "Possible Brute Force",
                "severity": "high",
                "description": f"{len(failures)} failed login attempts detected.",
                "entries": failures
            })

    return alerts

def detect_repeated_404_scanning(entries, threshold=5):
    errors_by_ip = defaultdict(list)

    for entry in entries:
        if entry["status"] == 404:
            errors_by_ip[entry["ip"]].append(entry)

    alerts = []

    for ip, errors in errors_by_ip.items():
        if len(errors) >= threshold:
            alerts.append({
                "ip": ip,
                "type": "Repeated 404 Scanning",
                "severity": "medium",
                "description": f"{len(errors)} 404 responses detected from same IP.",
                "entries": errors
            })

    return alerts

def run_all_detectors(entries):
    alerts = []

    alerts.extend(detect_admin_probing(entries))
    alerts.extend(detect_sql_injection_patterns(entries))
    alerts.extend(detect_path_traversal(entries))
    alerts.extend(detect_brute_force(entries))
    alerts.extend(detect_repeated_404_scanning(entries))

    return alerts