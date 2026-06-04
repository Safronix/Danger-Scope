import csv
import json
import os


def ensure_reports_folder():
    os.makedirs("reports", exist_ok=True)


def export_alerts_json(alerts, output_path="reports/alerts.json"):
    ensure_reports_folder()

    safe_alerts = []

    for alert in alerts:
        safe_alert = {
            "ip": alert["ip"],
            "type": alert["type"],
            "severity": alert["severity"],
            "description": alert["description"]
        }
        safe_alerts.append(safe_alert)

    with open(output_path, "w", encoding="utf-8") as file:
        json.dump(safe_alerts, file, indent=4)


def export_risk_summary_csv(risk_summary, output_path="reports/risk_summary.csv"):
    ensure_reports_folder()

    with open(output_path, "w", newline="", encoding="utf-8") as file:
        fieldnames = ["ip", "score", "risk_level"]
        writer = csv.DictWriter(file, fieldnames=fieldnames)

        writer.writeheader()
        writer.writerows(risk_summary)


def export_text_report(alerts, risk_summary, output_path="reports/security_report.txt"):
    ensure_reports_folder()

    with open(output_path, "w", encoding="utf-8") as file:
        file.write("DangerScope Security Report\n")
        file.write("===========================\n\n")

        file.write("Risk Summary by IP\n")
        file.write("------------------\n")

        for item in risk_summary:
            file.write(
                f"{item['ip']} | Score: {item['score']} | "
                f"Risk: {item['risk_level'].upper()}\n"
            )

        file.write("\nAlerts\n")
        file.write("------\n")

        for alert in alerts:
            file.write(f"\n[{alert['severity'].upper()}] {alert['type']}\n")
            file.write(f"IP: {alert['ip']}\n")
            file.write(f"{alert['description']}\n")