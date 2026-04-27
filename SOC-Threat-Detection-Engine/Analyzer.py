import re
import csv
from collections import defaultdict
from datetime import datetime

LOG_FILE = "logs/sample_auth.log"
OUTPUT_FILE = "output/alerts.csv"

failed_attempts = defaultdict(int)
alerts = []

def detect_failed_logins(line):
    match = re.search(r"Failed password for .* from (\d+\.\d+\.\d+\.\d+)", line)
    
    if match:
        ip = match.group(1)
        failed_attempts[ip] += 1

        if failed_attempts[ip] >= 5:
            alerts.append([
                datetime.now(),
                "HIGH",
                "Brute Force Attempt",
                ip,
                "MITRE T1110"
            ])

def detect_success_login_after_fail(line):
    match = re.search(r"Accepted password for .* from (\d+\.\d+\.\d+\.\d+)", line)

    if match:
        ip = match.group(1)

        if failed_attempts[ip] >= 3:
            alerts.append([
                datetime.now(),
                "CRITICAL",
                "Possible Compromised Account",
                ip,
                "MITRE T1078"
            ])

def analyze_logs():
    with open(LOG_FILE, "r") as file:
        for line in file:
            detect_failed_logins(line)
            detect_success_login_after_fail(line)

def export_alerts():
    with open(OUTPUT_FILE, "w", newline="") as file:
        writer = csv.writer(file)
        writer.writerow([
            "Timestamp",
            "Severity",
            "Alert",
            "Source IP",
            "MITRE Technique"
        ])
        writer.writerows(alerts)

if __name__ == "__main__":
    analyze_logs()
    export_alerts()
    print("Analysis completed. Alerts saved to output/alerts.csv")
