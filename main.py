
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

def display_results(ip_requests, endpoint, suspicious_activity):
    """
    Display the results in the terminal.
    """
    print("Requests per IP Address:")
    print(f"{'IP Address':<20}{'Request Count'}")
    for ip, count in ip_requests:
        print(f"{ip:<20}{count}")
    print()

    print("Most Frequently Accessed Endpoint:")
    print(f"{endpoint[0]} (Accessed {endpoint[1]} times)")
    print()

    print("Suspicious Activity Detected:")
    print(f"{'IP Address':<20}{'Failed Login Attempts'}")
    for ip, count in suspicious_activity:
        print(f"{ip:<20}{count}")
    print()

def main():
    # File paths
    log_file = "sample.log"
    output_csv = "log_analysis_results.csv"

    # Parse log file
    logs = parse_log_file(log_file)

    # Analyze data
    ip_requests = count_requests_by_ip(logs)
    endpoint = most_frequent_endpoint(logs)
    suspicious_activity = detect_suspicious_activity(logs)

    # Display and save results
    display_results(ip_requests, endpoint, suspicious_activity)
    save_to_csv(ip_requests, endpoint, suspicious_activity, output_csv)
    print(f"Results saved to {output_csv}")

if __name__ == "__main__":
    main()
