from parser import parse_log_file
from detectors import run_all_detectors
from risk_score import summarize_risk_by_ip


def main():
    log_entries = parse_log_file("sample_logs/suspicious_access.log")
    alerts = run_all_detectors(log_entries)
    risk_summary = summarize_risk_by_ip(alerts)

    print(f"Total log entries: {len(log_entries)}")
    print(f"Total alerts: {len(alerts)}")

    print("\nRisk Summary by IP")
    print("------------------")

    for item in risk_summary:
        print(f"{item['ip']} | Score: {item['score']} | Risk: {item['risk_level'].upper()}")

    print("\nAlerts")
    print("------")

    for alert in alerts:
        print()
        print(f"[{alert['severity'].upper()}] {alert['type']}")
        print(f"IP: {alert['ip']}")
        print(alert["description"])


if __name__ == "__main__":
    main()