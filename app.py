from flask import Flask, request, jsonify
import joblib  
from bs4 import BeautifulSoup
import requests
from urllib.parse import urlparse
import tldextract
import pandas as pd
import re

app = Flask(__name__)

# Load the trained model
model = joblib.load(open("phishing_model.pkl", "rb"))

# String-based feature extraction function
def extract_string_features(url):
    features = {}
    # Implement the string feature extraction logic
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
    except requests.RequestException:
        features['MissingTitle'] = 1
        features['InsecureForms'] = 0
    return features

# Combine all features
def extract_all_features(url):
    string_features = extract_string_features(url)
    content_features = extract_content_features(url)
    all_features = {**string_features, **content_features}
    return all_features

# API endpoint for prediction
@app.route('/classify', methods=['POST'])
def predict():
    data = request.get_json()
    url = data.get('url')
    if not url:
        return jsonify({"error": "No URL provided"}), 400

    # Extract features
    features = extract_all_features(url)

    # Convert features to a DataFrame
    features_df = pd.DataFrame([features])  # Ensure it matches training column order

    # Predict using the model
    prediction = model.predict(features_df)[0]

    # Convert prediction to a readable format
    result = "Phishing" if prediction == 1 else "Legitimate"

    return jsonify({"url": url, "prediction": result})
