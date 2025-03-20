import os
import joblib
import numpy as np
import re
from urllib.parse import urlparse
from sklearn.feature_extraction.text import TfidfVectorizer
import pandas as pd

# Load the pre-trained model
model_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'models', 'phishing_model.joblib')
model = None
vectorizer = None

def load_model():
    global model, vectorizer
    if model is None:
        try:
            model_data = joblib.load(model_path)
            model = model_data['model']
            vectorizer = model_data['vectorizer']
        except Exception as e:
            print(f"Error loading model: {e}")
            # Fallback to a simple rule-based classifier if model can't be loaded
            model = None
            vectorizer = None

def extract_features(url):
    """Extract features from URL for machine learning model"""
    features = {}
    
    # Parse URL
    parsed = urlparse(url)
    domain = parsed.netloc
    path = parsed.path
    
    # Basic features
    features['url_length'] = len(url)
    features['domain_length'] = len(domain)
    features['path_length'] = len(path)
    
    # Count special characters
    features['dots_count'] = url.count('.')
    features['hyphens_count'] = url.count('-')
    features['underscores_count'] = url.count('_')
    features['slash_count'] = url.count('/')
    features['question_count'] = url.count('?')
    features['equal_count'] = url.count('=')
    features['at_count'] = url.count('@')
    features['and_count'] = url.count('&')
    features['exclamation_count'] = url.count('!')
    features['space_count'] = url.count(' ')
    features['tilde_count'] = url.count('~')
    features['comma_count'] = url.count(',')
    features['plus_count'] = url.count('+')
    features['asterisk_count'] = url.count('*')
    features['hash_count'] = url.count('#')
    features['dollar_count'] = url.count('$')
    features['percent_count'] = url.count('%')
    
    # Check for HTTP/HTTPS
    features['has_https'] = int(url.startswith('https://'))
    
    # Check for suspicious words
    suspicious_words = ['login', 'secure', 'bank', 'account', 'verify', 'update', 'confirm']
    for word in suspicious_words:
        features[f'contains_{word}'] = int(word in url.lower())
    
    # IP address instead of domain
    features['has_ip'] = int(bool(re.match(r'\d+\.\d+\.\d+\.\d+', domain)))
    
    # Number of subdomains
    features['subdomain_count'] = domain.count('.') if domain.count('.') > 0 else 0
    
    return features

def features_to_vector(features):
    """Convert features dictionary to vector for ML model"""
    if vectorizer is None:
        # If no vectorizer is loaded, create a simple ordered vector
        return np.array([features[k] for k in sorted(features.keys())]).reshape(1, -1)
    else:
        # Use the trained vectorizer
        return vectorizer.transform([str(features)])

def predict_phishing(url):
    """Predict if URL is phishing using ML model"""
    load_model()
    
    features = extract_features(url)
    X = features_to_vector(features)
    
    if model is None:
        # Fallback to rule-based scoring if model couldn't be loaded
        score = 0
        # Add points for suspicious features
        if features['has_ip']: score += 0.3
        if not features['has_https']: score += 0.2
        if features['url_length'] > 100: score += 0.1
        if features['subdomain_count'] > 3: score += 0.15
        
        for word in ['login', 'secure', 'bank', 'account', 'verify']:
            if features.get(f'contains_{word}', 0) > 0:
                score += 0.1
                
        return {
            'is_phishing': score > 0.5,
            'confidence': score if score > 0.5 else 1 - score,
            'method': 'rule-based'
        }
    else:
        # Use ML model
        try:
            prediction = model.predict(X)[0]
            confidence = model.predict_proba(X)[0]
            conf_value = confidence[1] if prediction == 1 else confidence[0]
            return {
                'is_phishing': bool(prediction),
                'confidence': float(conf_value),
                'method': 'ml-model'
            }
        except Exception as e:
            print(f"Prediction error: {e}")
            return {
                'is_phishing': False,
                'confidence': 0.5,
                'method': 'error-fallback'
            }