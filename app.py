from flask import Flask, request, jsonify
import joblib
from bs4 import BeautifulSoup
import requests
from urllib.parse import urlparse
import pandas as pd
import re
import logging

app = Flask(__name__)

# Configure logging
logging.basicConfig(level=logging.INFO)

# Load the trained model and feature names
model = joblib.load("phishing_model.joblib")
feature_names = joblib.load("feature_names.joblib")  # List of feature names used during training

# String-based feature extraction function
def extract_string_features(url):
    features = {}
    features['UrlLength'] = len(url)
    features['NumDots'] = url.count('.')
    features['NumDash'] = url.count('-')
    features['NumUnderscore'] = url.count('_')
    features['NumNumericChars'] = sum(c.isdigit() for c in url)
    parsed_url = urlparse(url)
    hostname = parsed_url.hostname if parsed_url.hostname else ""
    features['HostnameLength'] = len(hostname)
    features['NumDashInHostname'] = hostname.count('-')
    features['NoHttps'] = 1 if not url.startswith('https://') else 0
    return features

# Content-based feature extraction function
def extract_content_features(url):
    features = {}
    try:
        response = requests.get(url, timeout=5)
        soup = BeautifulSoup(response.content, 'html.parser')
        features['MissingTitle'] = 1 if not soup.title or not soup.title.string.strip() else 0
        forms = soup.find_all('form')
        features['InsecureForms'] = sum(1 for form in forms if form.get('action', '').startswith('http://'))
    except requests.RequestException as e:
        logging.error(f"Error fetching content for URL: {url} - {e}")
        features['MissingTitle'] = 1
        features['InsecureForms'] = 0
    return features

# Runtime-Based feature extraction function
def extract_runtime_features(url):
    features = {
        'RightClickDisabled': 0,           # Default: Right-click is allowed
        'IframeOrFrame': 0,               # Default: No <iframe> or <frame> tags
        'PopUpWindow': 0,                 # Default: No pop-ups triggered
        'SubmitInfoToEmail': 0,           # Default: No email-based form actions
        'FakeLinkInStatusBar': 0,         # Default: No fake/misleading links
        'FrequentDomainNameMismatch': 0,  # Default: No frequent domain mismatches
    }
    return features

# Combine all features
def extract_all_features(url):
    string_features = extract_string_features(url)
    content_features = extract_content_features(url)
    runtime_features = extract_runtime_features(url)
    all_features = {**string_features, **content_features, **runtime_features}
    return all_features

# API endpoint for prediction
@app.route('/predict', methods=['POST'])
def predict():
    data = request.get_json()
    url = data.get('url')
    if not url:
        return jsonify({"error": "No URL provided"}), 400

    try:
        # Extract features
        features = extract_all_features(url)

        # Align features with model's expected feature set
        features_df = pd.DataFrame([features])
        features_df = features_df.reindex(columns=feature_names, fill_value=0)  # Ensure correct columns/order

        # Predict using the model
        prediction = model.predict(features_df)[0]

        # Convert prediction to a readable format
        result = "Phishing" if prediction == 1 else "Legitimate"

        return jsonify({"url": url, "prediction": result})
    
    except Exception as e:
        logging.error(f"Error during prediction for URL: {url} - {e}")
        return jsonify({"error": "An error occurred during prediction"}), 500

if __name__ == '__main__':
    app.run(debug=True)
