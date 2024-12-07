
import csv
from collections import defaultdict, Counter

# Configurable threshold for suspicious activity
FAILED_LOGIN_THRESHOLD = 10

def parse_log_file(file_path):
    """
    Parse the log file and extract relevant data.
    """
    logs = []
    with open(file_path, 'r') as file:
        for line in file:
            parts = line.strip().split(" ")
            ip = parts[0]
            endpoint = parts[6] if len(parts) > 6 else "-"
            status_code = parts[8] if len(parts) > 8 else "000"
            message = parts[-1] if len(parts) > 8 else "-"
            logs.append({"ip": ip, "endpoint": endpoint, "status": status_code, "message": message})
    return logs