class AlertSystem:
    def __init__(self):
        pass

    def generate_alerts(self, df, anomalies):
        """Logs and alerts for any identified anomalous logs."""
        print("\n" + "="*70)
        print("[!] AI ANOMALY DETECTION ALERTS [!]")
        print("="*70)
        
        # Attach anomaly labels to the original dataframe
        df['is_anomaly'] = anomalies
        anomalous_logs = df[df['is_anomaly']]
        
        if anomalous_logs.empty:
            print("Status: Normal. No anomalies detected.")
            print("="*70 + "\n")
            return
        
        for index, row in anomalous_logs.iterrows():
            print(f"[ALERT] {row['timestamp']} | IP: {row['ip_address']} | "
                  f"Status: {row['status_code']} | Message: '{row['message']}'")
            
        print("="*70)
        print(f"Summary: System generated {len(anomalous_logs)} alerts.")
        print("="*70 + "\n")
