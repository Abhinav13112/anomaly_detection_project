from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.preprocessing import OneHotEncoder
import pandas as pd
import numpy as np
import pickle
import os

class FeatureExtractor:
    def __init__(self, models_dir="models"):
        self.models_dir = models_dir
        # We cap features so it doesn't get excessively sparse
        self.vectorizer = TfidfVectorizer(max_features=50)
        # handle_unknown='ignore' ensures that unseen status codes do not crash the pipeline
        self.encoder = OneHotEncoder(sparse_output=False, handle_unknown='ignore')

    def fit(self, df):
        """Fits both the TF-IDF vectorizer on messages and OneHotEncoder on status codes."""
        print("Fitting TF-IDF vectorizer...")
        self.vectorizer.fit(df['message'])
        
        print("Fitting OneHotEncoder for status codes...")
        status_codes = df['status_code'].values.reshape(-1, 1)
        self.encoder.fit(status_codes)

    def transform(self, df):
        """Transforms logs into a numerical feature matrix using pre-fitted transformers."""
        # Transform log messages using pre-fitted TF-IDF vectorizer
        message_features = self.vectorizer.transform(df['message']).toarray()
        
        # Transform status codes using pre-fitted OneHotEncoder
        status_codes = df['status_code'].values.reshape(-1, 1)
        status_features = self.encoder.transform(status_codes)
        
        # Temporal features
        hour_feature = df['hour'].values.reshape(-1, 1)
        day_feature = df['day_of_week'].values.reshape(-1, 1)
        
        # Concatenate all numerical features
        features = np.hstack((
            message_features,
            status_features,
            hour_feature,
            day_feature
        ))
        
        return features

    def extract_features(self, df):
        """Legacy helper for fit-and-transform. Fits and returns feature matrix."""
        self.fit(df)
        return self.transform(df)

    def save(self):
        """Saves fitted vectorizer and encoder to disk."""
        os.makedirs(self.models_dir, exist_ok=True)
        
        vectorizer_path = os.path.join(self.models_dir, "vectorizer.pkl")
        encoder_path = os.path.join(self.models_dir, "encoder.pkl")
        
        with open(vectorizer_path, "wb") as f:
            pickle.dump(self.vectorizer, f)
        with open(encoder_path, "wb") as f:
            pickle.dump(self.encoder, f)
        
        print(f"Feature extractor components saved to {self.models_dir}/")

    def load(self):
        """Loads fitted vectorizer and encoder from disk."""
        vectorizer_path = os.path.join(self.models_dir, "vectorizer.pkl")
        encoder_path = os.path.join(self.models_dir, "encoder.pkl")
        
        if not os.path.exists(vectorizer_path) or not os.path.exists(encoder_path):
            raise FileNotFoundError(f"Fitted model files not found in {self.models_dir}/. Please run training first.")
            
        with open(vectorizer_path, "rb") as f:
            self.vectorizer = pickle.load(f)
        with open(encoder_path, "rb") as f:
            self.encoder = pickle.load(f)
            
        print(f"Feature extractor components loaded from {self.models_dir}/")

if __name__ == "__main__":
    from pre import LogPreprocessor
    pre = LogPreprocessor()
    df = pre.load_and_preprocess()
    ext = FeatureExtractor()
    features = ext.extract_features(df)
    print("Sample features:")
    print(features[:2])
