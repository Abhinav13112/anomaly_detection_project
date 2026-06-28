import pandas as pd
import os

class LogPreprocessor:
    def __init__(self, input_file="data/logs.csv"):
        self.input_file = input_file

    def load_and_preprocess(self):
        """Loads the CSV and preprocesses the log data returning a Pandas DataFrame."""
        print(f"Loading data from {self.input_file}...")
        if not os.path.exists(self.input_file):
            raise FileNotFoundError(f"Log file {self.input_file} not found. Please run log_collector.py first.")
            
        df = pd.read_csv(self.input_file)
        
        # Convert timestamp to datetime objects
        df['timestamp'] = pd.to_datetime(df['timestamp'])
        
        # Fill missing values if there are any
        df['message'] = df['message'].fillna('')
        df['status_code'] = df['status_code'].fillna(200).astype(int)
        
        # Optional: extract hour of day as a basic feature
        df['hour'] = df['timestamp'].dt.hour
        df['day_of_week'] = df['timestamp'].dt.dayofweek
        
        print(f"Loaded {len(df)} log entries.")
        return df

if __name__ == "__main__":
    preprocessor = LogPreprocessor()
    df = preprocessor.load_and_preprocess()
    print(df.head())
