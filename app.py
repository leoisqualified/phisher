from flask import Flask, request, jsonify
import joblib
from bs4 import BeautifulSoup
import requests
from urllib.parse import urlparse
import pandas as pd
import re
import logging
import tldextract

app = Flask(__name__)

# Configure logging
logging.basicConfig(level=logging.INFO)

# Load the trained model and feature names
model = joblib.load("phishing_model.joblib")
feature_names = joblib.load("feature_names.joblib")  # List of feature names used during training

# String-based feature extraction function
def extract_string_features(url):
    features = {}

    # Parse URL components
    parsed_url = urlparse(url)
    ext = tldextract.extract(url)
    hostname = parsed_url.hostname if parsed_url.hostname else ""
    path = parsed_url.path if parsed_url.path else ""

    # Basic string-based features
    features['UrlLength'] = len(url)
    features['NumDots'] = url.count('.')
    features['NumDash'] = url.count('-')
    features['NumUnderscore'] = url.count('_')
    features['NumPercent'] = url.count('%')
    features['NumNumericChars'] = sum(c.isdigit() for c in url)
    features['HostnameLength'] = len(hostname)
    features['NumDashInHostname'] = hostname.count('-')
    features['NoHttps'] = 1 if not url.startswith('https://') else 0
    features['IpAddress'] = 1 if re.match(r'\b\d{1,3}(\.\d{1,3}){3}\b', hostname) else 0

    # Subdomain and path analysis
    features['SubdomainLevel'] = len(ext.subdomain.split('.')) if ext.subdomain else 0
    features['PathLevel'] = len(path.split('/')) - 1
    features['HostnameLength'] = len(hostname)
    features['PathLength'] = len(path)
    features['QueryLength'] = len(parsed_url.query) if parsed_url.query else 0

    # Special character checks
    features['AtSymbol'] = url.count('@')
    features['TildeSymbol'] = url.count('~')
    features['DoubleSlashInPath'] = 1 if '//' in hostname else 0

    # Brand and random string checks
    features['RandomString'] = 1 if re.search(r'[a-zA-Z0-9]{7,}', hostname) else 0
    features['DomainInSubdomains'] = 1 if ext.domain in ext.subdomain else 0
    features['DomainInPaths'] = 1 if ext.domain in path else 0
    features['HttpsInHostname'] = 1 if 'https' in hostname else 0

    return features

# Content-based feature extraction function
def extract_content_features(url):
    features = {}
    try:
        # Make a request to the url
        response = requests.get(url, timeout=5)
        soup = BeautifulSoup(response.content, 'html.parser')

        # Title and form checks
        features['MissingTitle'] = 1 if not soup.title or not soup.title.string.strip() else 0
        forms = soup.find_all('form')
        features['InsecureForms'] = sum(1 for form in forms if form.get('action', '').startswith('http://'))

        # External links and resources
        total_links = soup.find_all('a')
        ext_links = [link for link in total_links if link.get('href', '').startswith('http')]
        features['PctExtHyperlinks'] = len(ext_links) / len(total_links) if total_links else 0

        total_resources = soup.find_all(['script', 'link', 'img'])
        ext_resources = [
            res for res in total_resources if res.get('src', '').startswith('http') or res.get('href', '').startswith('http')
        ]
        features['PctExtResourceUrls'] = len(ext_resources) / len(total_resources) if total_resources else 0

        # Images-only forms
        features['ImagesOnlyInForm'] = 1 if all(
            child.name == 'img' for form in forms for child in form.children
        ) else 0

    except requests.RequestException as e:
        logging.error(f"Error fetching content for URL: {url} - {e}")
        features['MissingTitle'] = 1
        features['InsecureForms'] = 0
        features['PctExtHyperlinks'] = 0
        features['PctExtResourceUrls'] = 0
        features['ImagesOnlyInForm'] = 0
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
