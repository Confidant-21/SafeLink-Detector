# SafeLink-Detector
A Streamlit and ML-based web app that analyzes URLs in real time. It extracts link features and classifies them as Legitimate, Suspicious, or Phishing to instantly detect online security threats.

# 🛡️ Phishing Websites Classification

## 1. Problem Statement

Phishing websites are designed to deceive users into revealing sensitive information such as usernames, passwords, banking credentials, and personal information. Since phishing websites can closely resemble legitimate websites, manually identifying them is difficult and unreliable.

The objective of this project is to build a **machine-learning-based phishing website classification system** that can classify websites as either:

- **Phishing**
- **Legitimate**

The project compares five different machine-learning algorithms and evaluates their performance using multiple classification metrics.

The models are evaluated using:

- Accuracy
- AUC
- Precision
- Recall
- F1 Score
- Matthews Correlation Coefficient (MCC)

The primary objective is to determine which model provides the best overall performance for phishing website detection.

---

# 2. Dataset Description

## Phishing Websites Dataset

The project uses the **Phishing Websites** dataset from the **UCI Machine Learning Repository**.

### Dataset Link

https://archive.ics.uci.edu/dataset/327/phishing

### Dataset Information

| Property | Description |
|---|---|
| Dataset Name | Phishing Websites |
| Repository | UCI Machine Learning Repository |
| Dataset ID | 327 |
| Number of Instances | 11,055 |
| Number of Features | 30 |
| Feature Type | Integer |
| Task | Binary Classification |
| Missing Values | None |

The dataset contains website-related characteristics that can be used to distinguish phishing websites from legitimate websites.

The features represent properties related to:

- URL structure
- Domain characteristics
- HTTPS usage
- Redirects
- Website behavior
- HTML characteristics
- DNS information
- Website traffic
- Search-engine indexing
- Page ranking
- External links

### Examples of Features

| Feature | Description |
|---|---|
| `having_ip_address` | Indicates whether an IP address is used instead of a normal domain |
| `url_length` | Represents the length of the website URL |
| `shortining_service` | Indicates whether a URL shortening service is used |
| `having_at_symbol` | Detects the presence of `@` in the URL |
| `double_slash_redirecting` | Detects suspicious double-slash redirection |
| `prefix_suffix` | Checks suspicious prefixes or suffixes in the domain |
| `having_sub_domain` | Represents subdomain characteristics |
| `sslfinal_state` | Represents SSL/HTTPS characteristics |
| `domain_registration_length` | Represents domain registration duration |
| `favicon` | Examines favicon behavior |
| `request_url` | Examines external resource requests |
| `url_of_anchor` | Examines anchor URLs |
| `links_in_tags` | Examines links inside HTML tags |
| `sfh` | Server form handler characteristics |
| `submitting_to_email` | Detects forms submitting information through email |
| `redirect` | Represents redirect behavior |
| `iframe` | Detects iframe usage |
| `age_of_domain` | Represents domain age |
| `dnsrecord` | Represents DNS information |
| `web_traffic` | Represents website traffic |
| `page_rank` | Represents page-ranking information |
| `google_index` | Indicates whether the website is indexed by Google |

---

# 3. GitHub Repository

The complete project, including the source code, model training notebook, trained model artifacts, Streamlit application, requirements and documentation, is maintained in the GitHub repository.

### GitHub Repository

**Add your GitHub repository link here:**

```text
https://github.com/<your-username>/<your-repository>
```

The repository contains all the required project files and can be used to reproduce and run the application.

### Repository Structure

```text
Phishing_Link_Checker/
│
├── app.py
├── phishing_checker.py
├── requirements.txt
├── README.md
│
├── artifacts/
│   ├── *.joblib
│   └── tuned_results.csv
│
└── notebooks/
    └── model_training.ipynb
```

---

# 4. Models Used

Five machine-learning classification models were trained and evaluated on the phishing websites dataset.

The following models were compared:

1. **Logistic Regression**
2. **Decision Tree**
3. **K-Nearest Neighbors (KNN)**
4. **Naive Bayes**
5. **Support Vector Machine (SVM)**

Each model was evaluated using the same test dataset and the same evaluation metrics.

---

## Evaluation Metrics

### Accuracy

Accuracy measures the percentage of total predictions that were classified correctly.

```text
Accuracy = Correct Predictions / Total Predictions
```

A higher value indicates better overall classification accuracy.

### AUC

AUC (Area Under the ROC Curve) measures the model's ability to distinguish between phishing and legitimate websites.

A value closer to **1.0** indicates better discrimination.

### Precision

Precision measures how reliable the model's phishing predictions are.

```text
Precision = TP / (TP + FP)
```

In this project:

> Of the websites predicted as phishing, how many were actually phishing?

High precision means fewer legitimate websites are incorrectly flagged as phishing.

### Recall

Recall measures how many actual phishing websites were successfully detected.

```text
Recall = TP / (TP + FN)
```

In this project:

> Of all actual phishing websites, how many did the model identify?

High recall is particularly important for phishing detection because missing an actual phishing website can be a serious security risk.

### F1 Score

F1 Score provides a balance between precision and recall.

```text
F1 = 2 × (Precision × Recall) / (Precision + Recall)
```

A higher F1 Score indicates a better balance between detecting phishing websites and avoiding false alarms.

### MCC

Matthews Correlation Coefficient (MCC) provides a balanced evaluation of binary classification performance.

Its range is:

```text
-1 → Completely incorrect
 0 → Random performance
+1 → Perfect prediction
```

A value closer to **1** indicates stronger overall classification quality.

---

# 5. Model Comparison

The following table presents the evaluation results for all five models.

| ML Model | Accuracy | AUC | Precision | Recall | F1 | MCC |
|---|---:|---:|---:|---:|---:|---:|
| Logistic Regression | 0.920 | 0.969 | 0.921 | 0.896 | 0.908 | 0.838 |
| Decision Tree | 0.937 | 0.981 | 0.926 | 0.932 | 0.929 | 0.872 |
| KNN | 0.944 | 0.986 | 0.957 | 0.914 | 0.935 | 0.887 |
| Naive Bayes | 0.679 | 0.962 | 0.581 | **0.997** | 0.734 | 0.493 |
| Support Vector Machine | **0.950** | **0.986** | 0.949 | 0.938 | **0.944** | **0.899** |

---

# 6. Observations on Model Performance

| ML Model | Observation about Model Performance |
|---|---|
| **Logistic Regression** | Achieved **92.0% accuracy** and an **F1 score of 0.908**. Precision (0.921) and recall (0.896) are reasonably balanced. It provides a reliable baseline but performs below Decision Tree, KNN, and SVM. |
| **Decision Tree** | Achieved **93.7% accuracy** and an **F1 score of 0.929**. Precision (0.926) and recall (0.932) are well balanced. Its AUC of 0.981 shows strong ability to distinguish phishing from legitimate websites. |
| **KNN** | Achieved **94.4% accuracy** and an **F1 score of 0.935**. It has the **highest precision (0.957)** among the five models, meaning its phishing predictions are highly reliable. Its AUC of 0.986 is also among the highest. |
| **Naive Bayes** | Achieved an extremely high **recall of 0.997**, meaning it detected almost all phishing websites. However, its precision is only **0.581**, resulting in many false positives. Its accuracy (0.679), F1 (0.734), and MCC (0.493) are the lowest overall. |
| **Support Vector Machine** | Achieved the **highest accuracy (0.950), F1 score (0.944), and MCC (0.899)**. Its precision (0.949) and recall (0.938) are also highly balanced. Its AUC of 0.986 is tied with KNN for the highest value, making SVM the strongest overall model. |

## Overall Winner

| Criteria | Best Model | Score |
|---|---|---:|
| Accuracy | **Support Vector Machine** | **0.950** |
| AUC | **KNN / Support Vector Machine** | **0.986** |
| Precision | **KNN** | **0.957** |
| Recall | **Naive Bayes** | **0.997** |
| F1 Score | **Support Vector Machine** | **0.944** |
| MCC | **Support Vector Machine** | **0.899** |

### 🏆 Overall Winner: Support Vector Machine

**Support Vector Machine (SVM)** is the overall winner for this dataset. It provides the best balance between precision and recall, achieving the highest **F1 Score of 0.944**, along with the highest accuracy and MCC.

Although Naive Bayes has the highest recall (0.997), its low precision (0.581) causes many legitimate websites to be incorrectly classified as phishing. KNN is the closest competitor to SVM, but SVM achieves a higher F1 score and stronger overall performance.

Therefore, **SVM is selected as the best-performing model for phishing website classification.**
---

# 7. Overall Winner for the Dataset

## 🏆 Support Vector Machine (SVM)

Based on the evaluation results, **Support Vector Machine is the overall winner for this dataset**.

SVM achieves the highest F1 Score:

```text
F1 Score = 0.944
```

It also achieves the highest accuracy and MCC:

```text
Accuracy = 0.950
MCC      = 0.899
```

Its AUC of **0.986** is tied with KNN for the highest value.

### Overall Model Ranking

| Rank | Model | F1 Score | Overall Performance |
|---:|---|---:|---|
| 🥇 1 | **Support Vector Machine** | **0.944** | Best overall |
| 🥈 2 | **KNN** | **0.935** | Excellent |
| 🥉 3 | **Decision Tree** | **0.929** | Very good |
| 4 | Logistic Regression | 0.908 | Good baseline |
| 5 | Naive Bayes | 0.734 | High recall but many false positives |

### Why SVM is the Winner

For phishing detection, relying only on accuracy is not sufficient.

The model should:

- Correctly detect phishing websites
- Avoid incorrectly flagging legitimate websites
- Maintain a good balance between precision and recall

SVM provides this balance better than the other models.

Although Naive Bayes achieves the highest recall (**0.997**), its precision is only **0.581**, meaning that many legitimate websites are incorrectly classified as phishing.

KNN is the closest competitor to SVM, with an F1 score of **0.935** and precision of **0.957**. However, SVM achieves a higher F1 score, accuracy, recall and MCC.

Therefore:

> **Support Vector Machine is selected as the overall winning model for the Phishing Websites dataset.**

---

# 8. Conclusion

The comparison of five machine-learning algorithms demonstrates that different models provide different trade-offs for phishing website detection.

- **Logistic Regression** provides a strong baseline.
- **Decision Tree** provides balanced performance.
- **KNN** provides excellent precision and strong overall performance.
- **Naive Bayes** achieves exceptional recall but produces many false positives.
- **SVM** provides the best overall balance across the evaluation metrics.

Therefore, based on the experimental results, **SVM is the recommended model for this project**.

The final selection is primarily supported by its **highest F1 Score of 0.944**, combined with the highest accuracy and MCC.

---

# 9. Application

The trained models are integrated into a Streamlit-based phishing link checker.

The application allows a user to enter a URL and inspect:

- Model prediction
- Phishing probability
- Probability-based decision
- Phishing-like feature count
- Suspicious feature count
- Feature assessment
- Independent security rules
- Final verdict
- Individual feature explanations

The application therefore provides not only a classification but also an explanation of the evidence behind the decision.

---

# 10. How to Run the Application

## Install Dependencies

```bash
pip install -r requirements.txt
```

## Run Streamlit

```bash
streamlit run app.py
```

The application will open in the browser at:

```text
http://localhost:8501
```

---

# 11. Application Data Flow

```text
User enters URL
        │
        ▼
URL Validation
        │
        ▼
Live Feature Extraction
        │
        ▼
Feature Vector
        │
        ▼
Selected ML Model
        │
        ├───────────────┐
        ▼               ▼
model.predict()    predict_proba()
        │               │
        ▼               ▼
Raw Prediction     Phishing Probability
        │               │
        └───────┬───────┘
                ▼
       Feature Rule Analysis
                │
                ▼
       Independent Risk Rules
                │
                ▼
          Final Verdict
                │
                ▼
       Streamlit Dashboard
```

The dashboard intentionally displays the **raw model prediction**, **probability**, and **final verdict** separately so that the user can understand how the final decision was reached.

---

# 12. Technologies Used

| Technology | Purpose |
|---|---|
| Python | Core programming language |
| Pandas | Data processing |
| Scikit-learn | Machine learning |
| Joblib | Model persistence |
| Streamlit | Web application |
| UCI ML Repository | Dataset |

---

# 13. Project Structure

```text
Phishing_Link_Checker/
│
├── app.py
├── phishing_checker.py
├── requirements.txt
├── README.md
│
├── artifacts/
│   ├── *.joblib
│   └── tuned_results.csv
│
└── notebooks/
    └── model_training.ipynb
```

---

# 14. Limitations

The model is trained on a historical phishing website dataset. Website behavior can change over time, and a website classified as legitimate by the model is not guaranteed to be safe.

Live website analysis can also be affected by:

- Website downtime
- Anti-bot protection
- DNS failures
- Redirects
- Dynamic content
- JavaScript-dependent behavior
- Changes in website structure

Therefore, the application should be considered a **machine-learning-based phishing risk assessment tool**, not a replacement for professional security software.

---

# 15. References

### UCI Machine Learning Repository

**Phishing Websites Dataset**

https://archive.ics.uci.edu/dataset/327/phishing

### Dataset Citation

Mohammad, R., McCluskey, L., & Thabtah, F. *Phishing Websites*. UCI Machine Learning Repository.

---

## 🏁 Final Result

**Overall Winner: Support Vector Machine (SVM)**

**Best F1 Score: 0.944**

**Accuracy: 95.0%**

**AUC: 98.6%**

**Precision: 94.9%**

**Recall: 93.8%**

**MCC: 89.9%**