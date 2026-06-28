import os
from src.log_collector import LogCollector
from src.pre import LogPreprocessor
from src.feature_extractor import FeatureExtractor
from src.anomaly_detector import AnomalyDetector
from src.alert_system import AlertSystem
from train import run_training

def main():
    print("+" + "-"*48 + "+")
    print("|   AI-Driven Anomaly Detection System Starting  |")
    print("+" + "-"*48 + "+\n")
    
    # 0. Check if models are trained, if not train them
    models_dir = "models"
    required_files = ["vectorizer.pkl", "encoder.pkl", "model.pkl"]
    models_exist = all(os.path.exists(os.path.join(models_dir, f)) for f in required_files)
    
    if not models_exist:
        print("Pre-trained models not found. Initializing auto-training...")
        run_training()
    else:
        print("Found existing models. Skipping training phase.\n")

    data_path = "data/logs.csv"
    
    # Phase 1: Data Simulation / Collection (Inference data)
    print(">>> PHASE 1: Data Collection (Incoming Logs)")
    collector = LogCollector(data_path)
    # Generate 500 logs with ~10% anomalies
    collector.generate_synthetic_logs(num_logs=500, anomaly_ratio=0.10)
    print("")
    
    # Phase 2: Preprocessing
    print(">>> PHASE 2: Preprocessing")
    preprocessor = LogPreprocessor(data_path)
    df = preprocessor.load_and_preprocess()
    print("")
    
    # Phase 3: Feature Extraction (Using Saved Transformers)
    print(">>> PHASE 3: Feature Extraction (Loading Saved Transformers)")
    extractor = FeatureExtractor(models_dir=models_dir)
    extractor.load()
    features = extractor.transform(df)
    print("")
    
    # Phase 4: Anomaly Detection Model (Using Saved Model)
    print(">>> PHASE 4: AI Model Evaluation (Loading Saved Model)")
    detector = AnomalyDetector(models_dir=models_dir)
    detector.load()
    anomalies = detector.detect(features)
    print("")
    
    # Phase 5: Alerting
    print(">>> PHASE 5: Alert Generation")
    alerter = AlertSystem()
    alerter.generate_alerts(df, anomalies)

if __name__ == "__main__":
    # Ensure current working directory is the project root to keep paths valid
    project_root = os.path.dirname(os.path.abspath(__file__))
    os.chdir(project_root)
    
    main()
