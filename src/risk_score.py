RISK_POINTS = {
    "Possible Brute Force": 30,
    "Possible SQL Injection": 35,
    "Possible Path Traversal": 35,
    "Admin Route Probing": 15,
    "Repeated 404 Scanning": 20,
}


def calculate_alert_score(alert):
    return RISK_POINTS.get(alert["type"], 5)


def classify_risk(score):
    if score >= 50:
        return "high"
    if score >= 25:
        return "medium"
    return "low"


def summarize_risk_by_ip(alerts):
    scores = {}

    for alert in alerts:
        ip = alert["ip"]
        scores[ip] = scores.get(ip, 0) + calculate_alert_score(alert)

    summary = []

    for ip, score in scores.items():
        summary.append({
            "ip": ip,
            "score": score,
            "risk_level": classify_risk(score)
        })

    summary.sort(key=lambda item: item["score"], reverse=True)
    return summary