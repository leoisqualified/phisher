import joblib
import pandas as pd
from app import extract_all_features  # Import the feature extraction function

# Load the trained model
model = joblib.load("phishing_model.joblib")
feature_names = joblib.load("feature_names.joblib")

# Define the test URL
test_url = "http://paypal-security-check-login-update.com/verify/account123"

# Extract features for the test URL
features = extract_all_features(test_url)
print("Extracted Features:", features)

# Convert features to DataFrame and reorder columns
features_df = pd.DataFrame([features])[feature_names]
print("Features DataFrame:\n", features_df)

# Make a prediction
prediction = model.predict(features_df)[0]
result = "Phishing" if prediction == 1 else "Legitimate"
print(f"Prediction for {test_url}: {result}")
