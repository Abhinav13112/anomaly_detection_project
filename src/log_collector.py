import csv
import random
import os
from datetime import datetime, timedelta

class LogCollector:
    def __init__(self, output_file="data/logs.csv"):
        self.output_file = output_file
        # Ensure directory exists
        os.makedirs(os.path.dirname(self.output_file), exist_ok=True)

    def generate_synthetic_logs(self, num_logs=1000, anomaly_ratio=0.05):
        """Generates synthetic logs and saves them to a CSV file."""
        print(f"Generating {num_logs} logs to {self.output_file}...")
        
        status_codes = [200, 201, 301, 302, 400, 401, 403, 404, 500, 502, 503]
        normal_status_weights = [0.6, 0.05, 0.05, 0.05, 0.05, 0.02, 0.02, 0.05, 0.05, 0.03, 0.03]
        
        # High likelihood of 5xx or 401/403 for anomalies
        anomaly_status_weights = [0.05, 0.0, 0.0, 0.0, 0.1, 0.3, 0.2, 0.05, 0.2, 0.05, 0.05]
        
        messages_normal = [
            "User logged in successfully",
            "Page rendered",
            "Data fetched from DB",
            "User updated profile",
            "Image uploaded"
        ]
        
        messages_anomaly = [
            "Multiple failed login attempts",
            "Database connection timeout",
            "Unauthorized access attempt",
            "Memory limit exceeded",
            "Invalid payload format"
        ]

        start_time = datetime.now() - timedelta(days=1)
        
        with open(self.output_file, mode='w', newline='', encoding='utf-8') as file:
            writer = csv.writer(file)
            writer.writerow(["timestamp", "ip_address", "status_code", "message"])
            
            for i in range(num_logs):
                # Step forward in time by a few seconds
                start_time += timedelta(seconds=random.randint(1, 30))
                
                is_anomaly = random.random() < anomaly_ratio
                
                ip_addr = f"192.168.1.{random.randint(1, 100)}" if not is_anomaly else f"10.0.{random.randint(1,255)}.{random.randint(1,255)}"
                
                if is_anomaly:
                    status = random.choices(status_codes, weights=anomaly_status_weights)[0]
                    msg = random.choice(messages_anomaly)
                else:
                    status = random.choices(status_codes, weights=normal_status_weights)[0]
                    msg = random.choice(messages_normal)
                
                writer.writerow([
                    start_time.strftime("%Y-%m-%d %H:%M:%S"),
                    ip_addr,
                    status,
                    msg
                ])
                
        print("Log generation complete.")

if __name__ == "__main__":
    collector = LogCollector()
    collector.generate_synthetic_logs()
