from sklearn.ensemble import IsolationForest
import pickle
import os

class AnomalyDetector:
    def __init__(self, contamination=0.05, random_state=42, models_dir="models"):
        self.contamination = contamination
        self.random_state = random_state
        self.models_dir = models_dir
        self.model = IsolationForest(contamination=self.contamination, random_state=self.random_state)

    def fit(self, features):
        """Fits the Isolation Forest model on the training features."""
        print("Training Isolation Forest model...")
        self.model.fit(features)

    def detect(self, features):
        """Runs predictions using the model (requires fit or load first)."""
        print("Running anomaly detection model inference...")
        predictions = self.model.predict(features)
        
        # Convert -1 (anomaly) and 1 (normal) predictions to True/False
        anomalies = (predictions == -1)
        
        print(f"Anomaly detection complete. Flagged {sum(anomalies)} anomalies.")
        return anomalies

    def save(self):
        """Saves the Isolation Forest model to disk."""
        os.makedirs(self.models_dir, exist_ok=True)
        model_path = os.path.join(self.models_dir, "model.pkl")
        
        with open(model_path, "wb") as f:
            pickle.dump(self.model, f)
            
        print(f"Anomaly detector model saved to {self.models_dir}/")

    def load(self):
        """Loads the Isolation Forest model from disk."""
        model_path = os.path.join(self.models_dir, "model.pkl")
        
        if not os.path.exists(model_path):
            raise FileNotFoundError(f"Fitted model file not found at {model_path}. Please run training first.")
            
        with open(model_path, "rb") as f:
            self.model = pickle.load(f)
            
        print(f"Anomaly detector model loaded from {self.models_dir}/")
