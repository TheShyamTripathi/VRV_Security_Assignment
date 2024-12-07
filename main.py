
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

def count_requests_by_ip(logs):
    """
    Count the number of requests per IP address.
    """
    ip_counts = Counter(log["ip"] for log in logs)
    return sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)

def most_frequent_endpoint(logs):
    """
    Identify the most frequently accessed endpoint.
    """
    endpoint_counts = Counter(log["endpoint"] for log in logs)
    most_common = endpoint_counts.most_common(1)
    return most_common[0] if most_common else ("-", 0)

def save_to_csv(ip_requests, endpoint, suspicious_activity, file_name):
    """
    Save the results to a CSV file.
    """
    with open(file_name, 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)

        # Write IP Requests
        writer.writerow(["IP Address", "Request Count"])
        writer.writerows(ip_requests)
        writer.writerow([])  # Blank line for separation

        # Write Most Accessed Endpoint
        writer.writerow(["Most Frequently Accessed Endpoint"])
        writer.writerow(["Endpoint", "Access Count"])
        writer.writerow(endpoint)
        writer.writerow([])

        # Write Suspicious Activity
        writer.writerow(["Suspicious Activity Detected"])
        writer.writerow(["IP Address", "Failed Login Count"])
        writer.writerows(suspicious_activity)

