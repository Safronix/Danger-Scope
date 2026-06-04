from parser import parse_log_file
from detectors import run_all_detectors
from risk_score import summarize_risk_by_ip
from report import export_alerts_json, export_risk_summary_csv, export_text_report


def main():
    log_entries = parse_log_file("sample_logs/suspicious_access.log")
    alerts = run_all_detectors(log_entries)
    risk_summary = summarize_risk_by_ip(alerts)

    export_alerts_json(alerts)
    export_risk_summary_csv(risk_summary)
    export_text_report(alerts, risk_summary)

    print("DangerScope analysis complete.")
    print(f"Total log entries: {len(log_entries)}")
    print(f"Total alerts: {len(alerts)}")
    print("Reports saved in the reports/ folder.")


if __name__ == "__main__":
    main()