# Import the required libraries
from flask import Flask, request, jsonify
import joblib
from bs4 import BeautifulSoup
import requests
from urllib.parse import urlparse
import pandas as pd
import re
import logging
import tldextract
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.action_chains import ActionChains
from selenium.webdriver.common.alert import Alert
from flask_cors import CORS
import spacy



app = Flask(__name__)

# Enable CORS
CORS(app)

# Configure logging
logging.basicConfig(level=logging.INFO)

# Load the trained model and feature names
model = joblib.load("phishing_model.joblib")
feature_names = joblib.load("feature_names.joblib")  # List of feature names used during training

BRAND_NAMES = ['paypal', 'amazon', 'facebook', 'google', 'microsoft', 'apple', 
               'bankofamerica', 'chase', 'wellsfargo', 'linkedin', 'ebay', 'twitter']

nlp = spacy.load("en_core_web_sm")

def detect_brand_name(hostname):
    # Check the static list first
    if any(brand in hostname.lower() for brand in BRAND_NAMES):
        return 1
    
    # If not found, use NLP-based detection
    doc = nlp(hostname)
    for ent in doc.ents:
        if ent.label_ == "ORG":  # Organization name detected
            return 1
    
    # If neither method detects a brand name
    return 0

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

    # Missing Features
    features['NumQueryComponents'] = len(parsed_url.query.split('&')) if parsed_url.query else 0
    features['NumAmpersand'] = url.count('&')
    features['NumHash'] = url.count('#')
    features['NumSensitiveWords'] = sum(word in url.lower() for word in ['secure', 'login', 'verify', 'account'])
    features['EmbeddedBrandName'] = detect_brand_name(hostname)
    return features

# Content-based feature extraction function
def extract_content_features(url):
    features = {}
    try:
        response = requests.get(url, timeout=5)
        soup = BeautifulSoup(response.content, 'html.parser')

        # Features to extract
        features['MissingTitle'] = 1 if not soup.title or not soup.title.string.strip() else 0
        forms = soup.find_all('form')
        features['InsecureForms'] = sum(1 for form in forms if form.get('action', '').startswith('http://'))
        features['ExtFavicon'] = 1 if soup.find('link', rel='icon') and 'http' in soup.find('link', rel='icon')['href'] else 0
        features['RelativeFormAction'] = sum(1 for form in forms if form.get('action', '').startswith('/'))
        features['ExtFormAction'] = sum(1 for form in forms if form.get('action', '').startswith('http://'))
        features['AbnormalFormAction'] = sum(1 for form in forms if not form.get('action', '').startswith(('http', '/')))
        features['PctNullSelfRedirectHyperlinks'] = len(soup.find_all('a', href='#')) / len(soup.find_all('a')) if soup.find_all('a') else 0

    except requests.RequestException:
        features['MissingTitle'] = 1
        features['InsecureForms'] = 0
        features['ExtFavicon'] = 0
        features['RelativeFormAction'] = 0
        features['ExtFormAction'] = 0
        features['AbnormalFormAction'] = 0
        features['PctNullSelfRedirectHyperlinks'] = 0
    return features



# Runtime Based feature extraction
def extract_runtime_features(url):
    features = {
        'RightClickDisabled': 0,
        'IframeOrFrame': 0,
        'PopUpWindow': 0,
        'SubmitInfoToEmail': 0,
        'FakeLinkInStatusBar': 0,
        'FrequentDomainNameMismatch': 0,
    }

    try:
        # Set up Selenium WebDriver
        options = Options()
        options.add_argument('--headless')  # Run in headless mode
        options.add_argument('--disable-gpu')
        options.add_argument('--no-sandbox')
        driver = webdriver.Chrome(service=Service('chromedriver'), options=options)

        # Open the URL
        driver.get(url)

        # 1. Check if right-click is disabled
        try:
            action = ActionChains(driver)
            action.context_click().perform()  # Attempt right-click
            features['RightClickDisabled'] = 0  # If no exception, right-click works
        except:
            features['RightClickDisabled'] = 1  # Right-click disabled

        # 2. Check for <iframe> or <frame> tags
        iframe_count = len(driver.find_elements(By.TAG_NAME, 'iframe')) + len(driver.find_elements(By.TAG_NAME, 'frame'))
        features['IframeOrFrame'] = 1 if iframe_count > 0 else 0

        # 3. Detect pop-ups
        try:
            driver.execute_script("window.open('about:blank', '_blank');")
            if len(driver.window_handles) > 1:
                features['PopUpWindow'] = 1
            driver.switch_to.window(driver.window_handles[0])  # Switch back
        except:
            features['PopUpWindow'] = 0

        # 4. Check for forms submitting data to email
        page_source = driver.page_source
        soup = BeautifulSoup(page_source, 'html.parser')
        forms = soup.find_all('form')
        features['SubmitInfoToEmail'] = sum(1 for form in forms if re.search(r'mailto:', form.get('action', '')))

        # 5. Detect fake links in the status bar
        links = soup.find_all('a', href=True)
        fake_links = [link for link in links if link['href'] and 'javascript:' in link['href'].lower()]
        features['FakeLinkInStatusBar'] = 1 if fake_links else 0

        # 6. Frequent domain name mismatch
        domain = requests.get(url).url.split('/')[2]
        resources = soup.find_all(['img', 'script', 'link'])
        mismatched_domains = sum(1 for res in resources if res.get('src', '').find(domain) == -1 and res.get('src', '').startswith('http'))
        features['FrequentDomainNameMismatch'] = 1 if mismatched_domains > len(resources) * 0.5 else 0

        # Add these to the extract_runtime_features function above

        # 7. Percentage of external resource URLs (Runtime)
        total_resources = len(resources)
        external_resources = sum(1 for res in resources if res.get('src', '').startswith('http') and domain not in res.get('src', ''))
        features['PctExtResourceUrlsRT'] = external_resources / total_resources if total_resources > 0 else 0

        # 8. Abnormal external form actions (Runtime)
        abnormal_forms = sum(1 for form in forms if form.get('action', '').startswith('http') and domain not in form.get('action', ''))
        features['AbnormalExtFormActionR'] = 1 if abnormal_forms > 0 else 0

        # 9. External metadata, scripts, and links (Runtime)
        external_meta_scripts_links = sum(
            1 for tag in soup.find_all(['meta', 'script', 'link']) 
            if tag.get('src', '').startswith('http') or tag.get('href', '').startswith('http')
        )
        total_meta_scripts_links = len(soup.find_all(['meta', 'script', 'link']))
        features['ExtMetaScriptLinkRT'] = external_meta_scripts_links / total_meta_scripts_links if total_meta_scripts_links > 0 else 0

        # 10. Null or self-redirect hyperlinks (Runtime)
        null_self_redirect_links = sum(1 for link in links if link['href'] in ['#', '/'])
        features['PctExtNullSelfRedirectHyperlinksRT'] = null_self_redirect_links / len(links) if links else 0


    except Exception as e:
        print(f"Runtime feature extraction failed for {url}: {e}")

    finally:
        try:
            driver.quit()
        except:
            pass  # If the driver isn't initialized, just ignore

    return features


# Combine all features
def extract_all_features(url):
    string_features = extract_string_features(url)
    content_features = extract_content_features(url)
    runtime_features = extract_runtime_features(url)
    all_features = {**string_features, **content_features, **runtime_features}
    return all_features

@app.route('/')
def home():
    return "Phishing Detection API is running."

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
        features_df = features_df.reindex(columns=feature_names, fill_value=0)  # Ensure correct columns order

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
