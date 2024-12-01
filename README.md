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
  - Logistic Regression
  - Decision Trees
  - Random Forest
  - Support Vector Machines (SVM)
  - Gradient Boosting (e.g., XGBoost)
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

- **Best Model**: [Specify the model achieving the highest accuracy/F1 score].
- **Accuracy Achieved**: [Mention the percentage accuracy].
- **Insights**:
  - [Key insights derived from the analysis, e.g., "Features such as URL length and SSL certification were highly indicative of phishing websites."]

---

## Challenges and Future Work

### Challenges

- Imbalanced Dataset: Addressed using techniques like oversampling (SMOTE) or undersampling.
- Feature Engineering: Required significant domain knowledge to derive useful features.

### Future Work

- Integrating the system with browser extensions for real-time detection.
- Expanding the dataset to include newer phishing patterns.
- Testing deep learning models for potential performance improvement.

---

## Conclusion

This project demonstrates the effectiveness of machine learning in detecting phishing websites. With proper feature selection and model optimization, the system achieves reliable performance, aiding in cybersecurity efforts.

---

## How to Run the Project

1. Clone the repository:

   ```bash
   https://github.com/leoisqualified/Phishing-Detection-Using-Machine-Learning.git
    ```

2. Install Required Dependencies:

    ```bash
    pip install -r requirements.txt
    ```