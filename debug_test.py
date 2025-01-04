import requests

# URL to test
test_urls = [
    "http://paypal-security-check-login-update.com/verify/account123",
    "https://example-legitimate-site.com",
    "http://phishy-site-with-popups.com"
]

for url in test_urls:
    response = requests.post("http://127.0.0.1:5000/predict", json={"url": url})
    print(f"Testing URL: {url}")
    print("Response:", response.json())
