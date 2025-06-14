import joblib
import logging
import pandas as pd
import requests
import re
import torch
import xgboost as xgb
from bs4 import BeautifulSoup
from flask import Flask, request, jsonify
from flask_cors import CORS
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


def get_bert_prediction(url):
    try:
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
        }
        response = requests.get(url, headers=headers, timeout=5)
        soup = BeautifulSoup(response.text, "html.parser")
        title = soup.title.string.strip() if soup.title and soup.title.string else ""
        text_snippet = soup.get_text(separator=' ', strip=True)[:500]
        full_input = f"{url} {title} {text_snippet}"

        logging.info(f"[BERT] Title: {title}")
        logging.info(f"[BERT] Snippet: {text_snippet[:100]}...")

    except Exception as e:
        logging.warning(f"[BERT] Content fetch failed: {e}")
        full_input = url

    inputs = tokenizer(full_input, return_tensors="pt", truncation=True, max_length=128)
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
    features = {}
    try:
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
        }
        response = requests.get(url, headers=headers, timeout=5)
        soup = BeautifulSoup(response.text, "html.parser")

        features['MissingTitle'] = 1 if not soup.title else 0

        forms = soup.find_all("form")
        features['InsecureForms'] = sum(1 for form in forms if form.get("action", "").startswith("http://"))
        features['RelativeFormAction'] = sum(1 for form in forms if form.get("action", "").startswith("/"))

        all_links = soup.find_all("a", href=True)
        ext_links = [link for link in all_links if urlparse(link["href"]).netloc not in url]
        features['PctExtHyperlinks'] = len(ext_links) / max(1, len(all_links))

        features['IframeOrFrame'] = 1 if soup.find("iframe") or soup.find("frame") else 0

        logging.info(f"[Content Features] Extracted: {features}")

    except Exception as e:
        logging.warning(f"[Content Features] Failed for {url}: {e}")

    return features



def extract_runtime_features(url):
    features = {}
    try:
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
        }
        response = requests.get(url, headers=headers, timeout=5)
        soup = BeautifulSoup(response.text, "html.parser")

        scripts = soup.find_all("script")
        features['RightClickDisabled'] = any("oncontextmenu" in script.text for script in scripts)

        fake_links = [a for a in soup.find_all("a", href=True) if "javascript:" in a["href"]]
        features['FakeLinkInStatusBar'] = len(fake_links)

        popups = [script for script in scripts if "window.open" in script.text]
        features['PopUpWindow'] = len(popups)

        logging.info(f"[Runtime Features] Extracted: {features}")

    except Exception as e:
        logging.warning(f"[Runtime Features] Failed for {url}: {e}")

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
        final_score = (0.4 * bert_score) + (0.6 * xgb_score)
        is_phishing = final_score > 0.5

        return jsonify({"url": url, "isPhishing": bool(is_phishing)})
    except Exception as e:
        logging.error(f"Error during prediction: {e}")
        return jsonify({"error": "An error occurred during prediction"}), 500


if __name__ == '__main__':
    app.run(debug=True)
