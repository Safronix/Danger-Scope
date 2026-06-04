from src.parser import parse_log_line

def test_parse_valid_log_line():
    line = '192.168.1.10 - - [26/May/2026:10:15:22] "GET / HTTP/1.1" 200'
    result = parse_log_line(line)

    assert result["ip"] == "192.168.1.10"
    assert result["method"] == "GET"
    assert result["path"] == "/"
    assert result["status"] == 200

def test_parse_invalid_log_line():
    line = "this is not a valid log line"
    result = parse_log_line(line)

    assert result is None