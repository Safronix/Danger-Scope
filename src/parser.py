import re

LOG_PATTERN = re.compile(
    r'(?P<ip>\S+) - - \[(?P<timestamp>[^\]]+)\] '
    r'"(?P<method>\S+) (?P<path>\S+) (?P<protocol>[^"]+)" '
    r'(?P<status>\d{3})'
)

def parse_log_line(line):
    """Parses line by line from a access log into a dictionary."""
    match = LOG_PATTERN.search(line)

    if not match:
        return None
    
    data = match.groupdict()
    data["status"] = int(data["status"])
    return data

def parse_log_file(file_path):
    """Parses an access log file and returns a list of dictionaries."""
    parsed_entries = []

    with open(file_path, "r", encoding="utf-8") as file:
        for line in file:
            parsed_line = parse_log_line(line.strip())

            if parsed_line:
                parsed_entries.append(parsed_line)

    return parsed_entries