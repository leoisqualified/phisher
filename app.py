import joblib
import logging
import pandas as pd
import requests
import re
import spacy
import tldextract
import torch
import xgboost as xgb
from bs4 import BeautifulSoup
from flask import Flask, request, jsonify
from flask_cors import CORS
from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from transformers import BertTokenizer, BertForSequenceClassification
from urllib.parse import urlparse

# Initialize Flask
app = Flask(__name__)
CORS(app)
logging.basicConfig(level=logging.INFO)

# Load Models
bert_model_name = "ealvaradob/bert-finetuned-phishing"
tokenizer = BertTokenizer.from_pretrained(bert_model_name)
bert_model = BertForSequenceClassification.from_pretrained(bert_model_name)

xgb_model = xgb.Booster()
xgb_model.load_model("xgboost_model.json")
feature_names = joblib.load("feature_names.joblib")

# nlp = spacy.load("en_core_web_sm")

# Selenium WebDriver Configuration
chrome_options = Options()
chrome_options.add_argument("--headless")
chrome_options.add_argument("--disable-gpu")

def get_bert_prediction(url):
    inputs = tokenizer(url, return_tensors="pt", truncation=True, max_length=128)
    outputs = bert_model(**inputs)
    probs = torch.softmax(outputs.logits, dim=1)
    return probs[0][1].item()

def extract_string_features(url):
    """ Extract features based on URL structure """
    features = {}
    parsed_url = urlparse(url)
    hostname = parsed_url.hostname or ""
    path = parsed_url.path or ""

    features['UrlLength'] = len(url)
    features['NumDots'] = url.count('.')
    features['NumDash'] = url.count('-')
    features['NumUnderscore'] = url.count('_')
    features['NumNumericChars'] = sum(c.isdigit() for c in url)
    features['NoHttps'] = 1 if not url.startswith('https://') else 0
    features['IpAddress'] = 1 if re.match(r'\b\d{1,3}(\.\d{1,3}){3}\b', hostname) else 0
    return features

def extract_content_features(url):
    """ Extract features from webpage content """
    features = {}
    try:
        response = requests.get(url, timeout=5)
        soup = BeautifulSoup(response.text, "html.parser")

        # Check if page has a title
        features['MissingTitle'] = 1 if not soup.title else 0

        # Count forms and insecure forms
        forms = soup.find_all("form")
        features['InsecureForms'] = sum(1 for form in forms if form.get("action", "").startswith("http://"))
        features['RelativeFormAction'] = sum(1 for form in forms if form.get("action", "").startswith("/"))

        # Count external links
        all_links = soup.find_all("a", href=True)
        ext_links = [link for link in all_links if urlparse(link["href"]).netloc not in url]
        features['PctExtHyperlinks'] = len(ext_links) / max(1, len(all_links))

        # Check for iframes
        features['IframeOrFrame'] = 1 if soup.find("iframe") or soup.find("frame") else 0

    except Exception as e:
        logging.warning(f"Failed to extract content features for {url}: {e}")

    return features

def extract_runtime_features(url):
    """ Extract JavaScript-related features using Selenium """
    features = {}
    try:
        driver = webdriver.Chrome(service=Service("chromedriver"), options=chrome_options)
        driver.get(url)

        # Detect right-click disabled
        right_click_disabled = driver.execute_script("""
            var disabled = false;
            document.oncontextmenu = function() { disabled = true; };
            return disabled;
        """)
        features['RightClickDisabled'] = int(right_click_disabled)

        # Detect pop-ups
        main_window = driver.current_window_handle
        features['PopUpWindow'] = 1 if len(driver.window_handles) > 1 else 0

        # Detect JavaScript redirects
        features['FakeLinkInStatusBar'] = sum(1 for a in driver.find_elements(By.TAG_NAME, "a")
                                              if "javascript:" in a.get_attribute("href"))

        driver.quit()
    except Exception as e:
        logging.warning(f"Failed to extract runtime features for {url}: {e}")

    return features

def extract_all_features(url):
    """ Combines all feature extraction methods """
    string_features = extract_string_features(url)
    content_features = extract_content_features(url)
    runtime_features = extract_runtime_features(url)
    all_features = {**string_features, **content_features, **runtime_features}
    return all_features

@app.route('/')
def home():
    return "Phishing Detection API is running."

@app.route('/predict', methods=['POST'])
def predict():
    data = request.get_json()
    url = data.get('url')
    if not url:
        return jsonify({"error": "No URL provided"}), 400

    try:
        # Get BERT prediction
        bert_score = get_bert_prediction(url)
        
        # Extract features for XGBoost
        features = extract_all_features(url)
        features_df = pd.DataFrame([features])
        features_df = features_df.reindex(columns=feature_names, fill_value=0)
        xgb_score = xgb_model.predict(xgb.DMatrix(features_df))[0]
        
        # Hybrid prediction
        final_score = (0.6 * bert_score) + (0.4 * xgb_score)
        is_phishing = final_score > 0.5
        
        return jsonify({"url": url, "isPhishing": bool(is_phishing)})
    except Exception as e:
        logging.error(f"Error during prediction: {e}")
        return jsonify({"error": "An error occurred during prediction"}), 500

if __name__ == '__main__':
    app.run(debug=True)
