import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction import DictVectorizer
from sklearn.pipeline import Pipeline
import joblib
import os

# Load the dataset
# Assuming you have a CSV with 'url' and 'is_phishing' columns
data = pd.read_csv('training-data.csv')

# Feature extraction function (same as in ml_model.py)
def extract_features(url):
    features = {}
    
    # Extract various features from the URL
    features['url_length'] = len(url)
    features['dots_count'] = url.count('.')
    features['hyphens_count'] = url.count('-')
    features['at_count'] = url.count('@')
    features['has_https'] = int(url.startswith('https://'))
    
    # More feature extraction logic...
    
    return features

# Process the dataset
X = data['URL'].apply(extract_features)
y = data['IsDomainIP']

# Create a pipeline with feature vectorization and model
pipeline = Pipeline([
    ('vectorizer', DictVectorizer()),
    ('classifier', RandomForestClassifier(n_estimators=100, random_state=42))
])

# Train the model
pipeline.fit(X, y)

# Save the model and vectorizer
os.makedirs('../../models', exist_ok=True)
joblib.dump({'model': pipeline, 'vectorizer': pipeline.named_steps['vectorizer']}, 
           '../../models/phishing_model.joblib')