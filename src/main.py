from parser import parse_log_file

def main():
    log_entries = parse_log_file("sample_logs/suspicious_access.log")

    for entry in log_entries:
        print(entry)

if __name__ == "__main__":
    main()
    