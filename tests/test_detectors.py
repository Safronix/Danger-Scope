from src.detectors import detect_brute_force, detect_sql_injection_patterns


def test_detect_brute_force():
    entries = []

    for _ in range(5):
        entries.append({
            "ip": "192.168.1.10",
            "timestamp": "26/May/2026:10:15:22",
            "method": "POST",
            "path": "/login",
            "protocol": "HTTP/1.1",
            "status": 401
        })

    alerts = detect_brute_force(entries)

    assert len(alerts) == 1
    assert alerts[0]["type"] == "Possible Brute Force"


def test_detect_sql_injection_pattern():
    entries = [{
        "ip": "88.12.44.2",
        "timestamp": "26/May/2026:10:17:01",
        "method": "GET",
        "path": "/search?q=' OR 1=1 --",
        "protocol": "HTTP/1.1",
        "status": 400
    }]

    alerts = detect_sql_injection_patterns(entries)

    assert len(alerts) == 1
    assert alerts[0]["type"] == "Possible SQL Injection"