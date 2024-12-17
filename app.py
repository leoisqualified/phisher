from flask import Flask, request, jsonify
import joblib
import pandas as pd
import re
import tldextract

# Load the trained model
model = joblib.load('phishing_model.pkl')

# Initialize Flask app
app = Flask(__name__)

# Feature extraction function
def extract_features(url):
    features = {}
    
    # Feature 1: URL length
    features['urllength'] = len(url)
    
    # Feature 2: Number of dashes ('-')
    features['numdash'] = url.count('-')
    
    # Feature 3: Number of dashes in hostname
    extracted = tldextract.extract(url)
    hostname = extracted.domain + '.' + extracted.suffix
    features['numdashinhostname'] = hostname.count('-')
    
    # Feature 4: Number of underscores ('_')
    features['numunderscore'] = url.count('_')
    
    # Feature 5: Number of tilde symbols ('~')
    features['tildesymbol'] = url.count('~')
    
    # Feature 6: Number of '@' symbols
    features['atsymbol'] = url.count('@')
    
    # Add more features here as needed...
    features['https'] = 1 if url.startswith('https://') else 0
    
    return features

# Define an endpoint for URL classification
@app.route('/classify', methods=['POST'])
def classify_url():
    data = request.json
    url = data.get('url', '')

    if not url:
        return jsonify({'error': 'URL is missing'}), 400
    
    # Extract features
    features = extract_features(url)
    features_df = pd.DataFrame([features])
    
    # Predict using the model
    prediction = model.predict(features_df)[0]
    return jsonify({'phishing': bool(prediction)})

if __name__ == '__main__':
    app.run(debug=True)
