import joblib
import logging
import pandas as pd
import requests
import re
import secrets
import torch
import xgboost as xgb
from bs4 import BeautifulSoup
from flask import Flask, request, jsonify, render_template, abort
from flask_cors import CORS
from transformers import BertTokenizer, BertForSequenceClassification
from urllib.parse import urlparse, parse_qs
from playwright.sync_api import sync_playwright

# App initialization
app = Flask(__name__)
CORS(app)
logging.basicConfig(level=logging.INFO)

# Database configuration
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///phishing_logs.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False  # (optional, but good practice)

# Import models app
from models import db, URLLog, Blacklist, Company
db.init_app(app)

# Ensure tables are created inside app context
with app.app_context():
    db.create_all()


# Load Models
bert_model_name = "ealvaradob/bert-finetuned-phishing"
tokenizer = BertTokenizer.from_pretrained(bert_model_name)
bert_model = BertForSequenceClassification.from_pretrained(bert_model_name)

xgb_model = xgb.Booster()
xgb_model.load_model("xgboost_model.json")
feature_names = joblib.load("feature_names.joblib")


# === Constants ===
SENSITIVE_WORDS = [
    "secure", "account", "webscr", "login", "signin", "banking", "confirm",
    "password", "update", "verify", "security", "ebayisapi", "paypal"
]

BRAND_NAMES = [
    "paypal", "google", "facebook", "apple", "amazon", "microsoft", "bankofamerica"
]

SAFE_DOMAINS = ["chatgpt.com", "openai.com", "google.com", "microsoft.com"]


# === Fetching ===
def fetch_with_playwright(url):
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            page = browser.new_page()
            page.goto(url, timeout=10000)
            page.wait_for_load_state("networkidle")
            html = page.content()
            browser.close()
            return BeautifulSoup(html, "html.parser")
    except Exception as e:
        logging.warning(f"[Playwright] JS rendering failed: {e}")
        return None


def fetch_soup(url):
    try:
        headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}
        response = requests.get(url, headers=headers, timeout=5)
        soup = BeautifulSoup(response.text, "html.parser")
        title = soup.title.string.strip() if soup.title and soup.title.string else ""
        text_snippet = soup.get_text(separator=' ', strip=True)[:500]

        if "enable javascript" in text_snippet.lower() or not title:
            raise ValueError("Content appears JS-protected. Triggering fallback...")
        return soup
    except Exception as e:
        logging.warning(f"[Fetch] Primary fetch failed: {e}")
        return fetch_with_playwright(url)


# === Feature Extraction ===
def extract_string_features(url):
    parsed = urlparse(url)
    hostname = parsed.hostname or ""
    return {
        "UrlLength": len(url),
        "NumDots": url.count("."),
        "NumDash": url.count("-"),
        "NumUnderscore": url.count("_"),
        "NumNumericChars": sum(c.isdigit() for c in url),
        "NoHttps": int(not url.startswith("https://")),
        "IpAddress": int(bool(re.match(r'\b\d{1,3}(\.\d{1,3}){3}\b', hostname)))
    }


def extract_additional_url_features(url):
    parsed = urlparse(url)
    hostname = parsed.hostname or ""
    path = parsed.path or ""
    query = parsed.query or ""

    domain_parts = hostname.split(".")
    main_domain = ".".join(domain_parts[-2:]) if len(domain_parts) >= 2 else hostname
    subdomains = domain_parts[:-2]

    return {
        "SubdomainLevel": max(0, len(subdomains)),
        "PathLevel": path.count("/"),
        "NumDashInHostname": hostname.count("-"),
        "AtSymbol": url.count("@"),
        "TildeSymbol": url.count("~"),
        "NumPercent": url.count("%"),
        "NumQueryComponents": len(parse_qs(query)),
        "NumAmpersand": url.count("&"),
        "NumHash": url.count("#"),
        "DomainInSubdomains": int(any(main_domain in sd for sd in subdomains)),
        "DomainInPaths": int(main_domain in path),
        "HttpsInHostname": int("https" in hostname.lower()),
        "HostnameLength": len(hostname),
        "PathLength": len(path),
        "QueryLength": len(query),
        "DoubleSlashInPath": int("//" in path),
        "NumSensitiveWords": sum(word in url.lower() for word in SENSITIVE_WORDS),
        "EmbeddedBrandName": sum(brand in url.lower() for brand in BRAND_NAMES)
    }


def extract_content_features(soup, url):
    features = {}
    try:
        features["MissingTitle"] = int(not soup.title)

        forms = soup.find_all("form")
        features["InsecureForms"] = sum(1 for f in forms if f.get("action", "").startswith("http://"))
        features["RelativeFormAction"] = sum(1 for f in forms if f.get("action", "").startswith("/"))

        all_links = soup.find_all("a", href=True)
        ext_links = [a for a in all_links if urlparse(a["href"]).netloc not in url]
        features["PctExtHyperlinks"] = len(ext_links) / max(1, len(all_links))

        features["IframeOrFrame"] = int(bool(soup.find("iframe") or soup.find("frame")))
    except Exception as e:
        logging.warning(f"[Content Features] Error: {e}")
    return features


def extract_runtime_features(soup):
    features = {}
    try:
        scripts = soup.find_all("script")
        features["RightClickDisabled"] = any("oncontextmenu" in script.text.lower() for script in scripts)
        features["FakeLinkInStatusBar"] = sum(1 for a in soup.find_all("a", href=True) if "javascript:" in a["href"].lower())
        features["PopUpWindow"] = sum(1 for s in scripts if "window.open" in s.text.lower())
    except Exception as e:
        logging.warning(f"[Runtime Features] Error: {e}")
    return features


def extract_extended_content_features(soup, url):
    features = {}
    try:
        # External resource URLs
        tags = soup.find_all(["script", "img", "link"])
        urls = [t.get("src") or t.get("href") for t in tags if t.get("src") or t.get("href")]
        ext = [u for u in urls if urlparse(u).netloc and urlparse(u).netloc not in url]
        features["PctExtResourceUrls"] = len(ext) / max(1, len(urls))

        # External favicon
        favicons = soup.find_all("link", rel=lambda val: val and "icon" in val.lower())
        features["ExtFavicon"] = int(any(urlparse(f.get("href", "")).netloc not in url for f in favicons))

        # Form behavior
        forms = soup.find_all("form")
        ext_forms = abnormal = nulls = mails = image_only = 0

        for f in forms:
            action = f.get("action", "").lower()
            if action.startswith("mailto:"):
                mails += 1
            if action in ["", "#", "javascript:void(0)"]:
                nulls += 1
            if action == "" or action.startswith("javascript"):
                abnormal += 1
            if action and urlparse(action).netloc and urlparse(action).netloc not in url:
                ext_forms += 1
            if f.find_all("img") and not f.find_all(["input", "textarea", "select"]):
                image_only += 1

        features["ExtFormAction"] = ext_forms
        features["AbnormalFormAction"] = abnormal
        features["PctNullSelfRedirectHyperlinks"] = nulls / max(1, len(forms))
        features["SubmitInfoToEmail"] = mails
        features["ImagesOnlyInForm"] = image_only

        # FrequentDomainNameMismatch
        all_links = soup.find_all("a", href=True)
        page_domain = urlparse(url).netloc
        mismatches = sum(1 for a in all_links if urlparse(a["href"]).netloc not in [page_domain, ""])
        features["FrequentDomainNameMismatch"] = mismatches / max(1, len(all_links))
    except Exception as e:
        logging.warning(f"[Extended Content Features] Error: {e}")
    return features


# === Main Feature Extraction ===
def extract_all_features(url):
    soup = fetch_soup(url)

    features = {}
    features.update(extract_string_features(url))
    features.update(extract_additional_url_features(url))

    if soup:
        features.update(extract_content_features(soup, url))
        features.update(extract_runtime_features(soup))
        features.update(extract_extended_content_features(soup, url))
    else:
        logging.warning(f"[Extract All] No content parsed for {url}")

    return features


# === BERT Classifier ===
def get_bert_prediction(url):
    soup = fetch_soup(url)

    if soup:
        title = soup.title.string.strip() if soup.title and soup.title.string else ""
        text_snippet = soup.get_text(separator=" ", strip=True)[:500]
        full_input = f"{url} {title} {text_snippet}"
    else:
        full_input = url

    inputs = tokenizer(full_input, return_tensors="pt", truncation=True, max_length=128)
    outputs = bert_model(**inputs)
    probs = torch.softmax(outputs.logits, dim=1)
    return probs[0][1].item()


# === Domain Check ===
def is_safe_domain(url):
    domain = urlparse(url).netloc
    return any(safe in domain for safe in SAFE_DOMAINS)

# ============ ROUTES ============
# Home Route
@app.route('/')
def home():
    return "Phishing Detection API is running."

# Predict Route
@app.route('/predict', methods=['POST'])
def predict():
    data = request.get_json()
    url = data.get('url')
    if not url:
        return jsonify({"error": "No URL provided"}), 400

    # 🔐 Step 1: Authenticate company via API key
    api_key = request.headers.get("X-API-KEY")
    if not api_key:
        return jsonify({"error": "Missing API key"}), 401

    company = Company.query.filter_by(api_key=api_key).first()
    if not company:
        return jsonify({"error": "Invalid API key"}), 403

    try:
        # 🤖 Step 2: Get BERT score
        bert_score = get_bert_prediction(url)

        # 📊 Step 3: Extract features & XGBoost prediction
        features = extract_all_features(url)
        features_df = pd.DataFrame([features])
        features_df = features_df.reindex(columns=feature_names, fill_value=0)
        xgb_score = xgb_model.predict(xgb.DMatrix(features_df))[0]

        # 🧠 Step 4: Combine scores
        final_score = (0.6 * bert_score) + (0.4 * xgb_score)
        verdict = 'phishing' if final_score > 0.5 else 'safe'

        # 📝 Step 5: Log URL to DB with company_id
        log = URLLog(
            url=url,
            prediction_score=final_score,
            verdict=verdict,
            company_id=company.id
        )
        db.session.add(log)
        db.session.commit()

        # 📤 Step 6: Return result
        return jsonify({
            "url": url,
            "score": float(final_score),
            "verdict": verdict
        })

    except Exception as e:
        logging.error(f"Error during prediction: {e}")
        return jsonify({"error": "An error occurred during prediction"}), 500

def get_company_from_request():
    api_key = request.headers.get('X-API-KEY')
    if not api_key:
        abort(401, description="Missing API Key")
    company = Company.query.filter_by(api_key=api_key).first()
    if not company:
        abort(403, description="Invalid API Key")
    return company

# Black List Routes
@app.route('/blacklist/add', methods=['POST'])
def add_to_blacklist():
    url = request.json['url']
    reason = request.json.get('reason', 'manual')
    if not Blacklist.query.filter_by(url=url).first():
        db.session.add(Blacklist(url=url, reason=reason))
        db.session.commit()
        return jsonify({'message': f'{url} successfully blacklisted.'})
    return jsonify({'message': f'{url} is already blacklisted.'})

# Admin Routes
@app.route('/admin/logs/<int:company_id>')
def view_company_logs(company_id):
    logs = URLLog.query.filter_by(company_id=company_id).order_by(URLLog.timestamp.desc()).limit(100).all()
    return render_template('admin_logs.html', logs=logs)

@app.route('/admin/create-company', methods=['POST'])
def create_company():
    data = request.get_json()
    company_name = data.get('name')

    if not company_name:
        return jsonify({'error': 'Company name is required'}), 400

    # Check if the company already exists
    existing = Company.query.filter_by(name=company_name).first()
    if existing:
        return jsonify({'error': 'Company already exists'}), 400

    # Generate a secure API key
    api_key = secrets.token_hex(32)

    new_company = Company(name=company_name, api_key=api_key)
    db.session.add(new_company)
    db.session.commit()

    return jsonify({
        'message': 'Company created successfully',
        'company': {
            'name': company_name,
            'api_key': api_key
        }
    }), 201

@app.route('/admin/create-company-form')
def create_company_form():
    return render_template('admin_create_company.html')


if __name__ == '__main__':
    app.run(debug=True)
