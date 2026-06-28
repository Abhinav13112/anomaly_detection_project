import os
from src.log_collector import LogCollector
from src.pre import LogPreprocessor
from src.feature_extractor import FeatureExtractor
from src.anomaly_detector import AnomalyDetector

def run_training():
    print("+" + "-"*48 + "+")
    print("|            Starting Offline Model Training     |")
    print("+" + "-"*48 + "+\n")
    
    # 1. Collect / Generate historical logs for training
    data_path = "data/train_logs.csv"
    print(">>> Phase 1: Generating training baseline data...")
    collector = LogCollector(data_path)
    # Generate 1000 logs for training baseline
    collector.generate_synthetic_logs(num_logs=1000, anomaly_ratio=0.08)
    print("")
    
    # 2. Preprocessing
    print(">>> Phase 2: Preprocessing training logs...")
    preprocessor = LogPreprocessor(data_path)
    df = preprocessor.load_and_preprocess()
    print("")
    
    # 3. Fit Feature Extractor and save
    print(">>> Phase 3: Fitting & saving Feature Extractor...")
    extractor = FeatureExtractor(models_dir="models")
    extractor.fit(df)
    extractor.save()
    features = extractor.transform(df)
    print("")
    
    # 4. Fit Anomaly Detector and save
    print(">>> Phase 4: Fitting & saving Anomaly Detector model...")
    detector = AnomalyDetector(contamination=0.08, random_state=42, models_dir="models")
    detector.fit(features)
    detector.save()
    print("")
    
    print("+" + "-"*48 + "+")
    print("|            Offline Model Training Completed!   |")
    print("+" + "-"*48 + "+\n")

if __name__ == "__main__":
    # Ensure current working directory is the project root to keep paths valid
    project_root = os.path.dirname(os.path.abspath(__file__))
    os.chdir(project_root)
    
    run_training()
