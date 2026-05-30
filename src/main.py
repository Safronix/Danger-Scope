from parser import parse_log_file
from detectors import run_all_detectors

def main():
    log_entries = parse_log_file("sample_logs/suspicious_access.log")
    alerts = run_all_detectors(log_entries)

    print(f"Total log entries: {len(log_entries)}")
    print(f"Total alerts: {len(alerts)}")

    for alert in alerts:
        print()
        print(f"[{alert['severity'].upper()}] {alert['type']}")
        print(f"IP: {alert['ip']}")
        print(alert["description"])

if __name__ == "__main__":
    main()
