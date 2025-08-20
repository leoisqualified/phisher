# Phishing Detection System Using Machine Learning

## Project Overview

This project involves developing a **Phishing Detection System** using machine learning techniques. Phishing is a fraudulent attempt to obtain sensitive information, and detecting it effectively is crucial to protect users online. By leveraging Python and its powerful libraries, we analyze web-based data to identify phishing websites.

---

## Features and Objectives

- **Objective**: Accurately classify websites as phishing or legitimate using supervised machine learning.
- **Key Features**:
  - Extraction of URL-based, content-based, and domain-based features.
  - Implementation of multiple machine learning models to achieve optimal performance.
  - Visualization of data insights to improve feature selection and understanding.

---

## Libraries Used

- **Scikit-learn**: For implementing machine learning algorithms and evaluation metrics.
- **Pandas**: For data manipulation and preprocessing.
- **Matplotlib & Seaborn**: For creating informative data visualizations.
- **NumPy**: For numerical computations.

---

## Dataset

- **Source**: [Mention the dataset source or URL if publicly available].
- **Structure**: The dataset contains features such as URL length, presence of special characters, domain age, SSL certificate details, and a target label indicating whether the website is phishing (1) or legitimate (0).

---

## Methodology

### 1. Data Preprocessing

- **Handling Missing Values**: Cleaned missing or inconsistent entries.
- **Feature Scaling**: Normalized numerical features for better model performance.
- **Encoding Categorical Features**: Converted non-numeric data into a format suitable for machine learning models.

### 2. Exploratory Data Analysis (EDA)

- **Correlation Analysis**: Visualized feature relationships using heatmaps.
- **Feature Distribution**: Plotted histograms and boxplots to understand feature variance.
- **Outlier Detection**: Identified and handled outliers to reduce noise.

### 3. Model Selection

- **Algorithms Used**:
  - Gradient Boosting (XGBoost)
  - BERT
- **Evaluation Metrics**:
  - Accuracy
  - Precision, Recall, and F1 Score
  - ROC-AUC Score

### 4. Training and Testing

- **Train-Test Split**: Split the dataset into 80% training and 20% testing.
- **Cross-Validation**: Used k-fold cross-validation to prevent overfitting.

### 5. Results Visualization

- Confusion Matrix: Visualized true positives, false positives, etc.
- ROC Curve: Plotted to compare the performance of different models.

---

## Results

- **Best Model**: Per the previous research work, the XGB was the best classifier model, achieving an accuracy of 98%
- **Accuracy Achieved**: [Mention the percentage accuracy].
- **Insights**:
  - Features such as URL length and presence of HTTPS protocol were highly indicative of phishing websites.

---

## System Architecture

- **Machine Learning (ML) Engine:** Evaluates and flags active webpages.
- **Flask Web App:** Development Environment for the web extension. Includes an admin interface for companies to log in and view url logs and control access.
- **Database (SQLite):** Stores logs of analyzed URLs, companies, admins, and blacklist entries.
- **Company API Key System:** Each company gets a secure API key to log phishing events.
- **Admin Panel:** Allows companies to:
  - Log in securely
  - View their own logs (scoped by company_id)
  - Blacklist suspicious URLs
  - Create new companies (if superadmin)

## User Roles & Access Control

- **Admin (per company)**
  - Logs in via `/admin/login`
  - Views only their company logs via `/admin/logs`
  - Can blacklist URLs suspicious to their company
- **API Access**
  - Companies can use their API Key (`X-API-KEY` header) to interact programmatically with the system.

## Database Models

- Company
  - `id`, `name`, `api_key`
- AdminUser
  - `id`, `email`, `password_hash`, `company_id`
- URLLog
  - `id`, `url`, `verdict`,`prediction_score`, `timestamp`, `company_id`
- Blacklist
  - `id`, `url`, `reason`

## Routes Overview

### Authentication & Company

- `GET /admin/create-company-form` -> Company creation form
- `POST /admin/create-company` -> Create a company (superadmin)
- `POST /company/login` -> Login for admins

### Logs

- `GET /company/dashboard` -> Company URLLogs

### Blacklist

- `POST /blacklist/add` -> Blacklist a URL (admin only)

### Frontend Templates

- `company_login.html` -> Secure login page for admins
- `company_dashboard.html` -> Displays phishing logs (company-specific) with blacklist actions.
- `admin_create_company.html` -> Simple company creation form.

### Security Notes

- Passwords are stored as hashed values using Werkzeug.
- API keys are randomly generated using Python's `secrets` library.
- Admins onlly see their company's logs.
- Blacklisting ensures suspicious URLs can be blocked for future checks.

## Challenges and Future Work

### Challenges

- Feature Engineering: Required significant domain knowledge to derive useful features.
- Most Websites are Javascript protected to prevent scraping and data collection on these websites.

### Future Work

- Expanding the dataset to include newer phishing patterns.
- Testing deep learning models for potential performance improvement.
- Leveraging Intrusive Detection System to allow the extension function at the network level.
- JWT-based API auth (instead of API keys in headers)
- Emails alerts for blacklisted URLs

---

## Conclusion

This project demonstrates the effectiveness of machine learning in detecting phishing websites. With proper feature selection and model optimization, the system achieves reliable performance, aiding in cybersecurity and fighting against phishing.

---

## How to Run the Project

```bash
# clone repository
git clone https://github.com/leoisqualified/phisher.git
cd phisher

# install dependencies
   pip install -r requirements.txt

# run server
python3 phisher/app.py
```

- Apps runs on: `http://127.0.0.1:5000`
- Admin panel: `http://127.0.0.1:5000/company/login`
