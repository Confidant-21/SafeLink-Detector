# SafeLink-Detector
A Streamlit and ML-based web app that analyzes URLs in real time. It extracts link features and classifies them as Legitimate, Suspicious, or Phishing to instantly detect online security threats.

The application analyzes a website URL using a trained phishing-classification model and combines:

1. **Machine-learning prediction**
2. **Phishing probability**
3. **Live URL/domain/page features**
4. **Feature-level phishing and suspicious signals**
5. **Independent security rules**
6. **A conservative final verdict**

The goal is not only to answer:

> **"Is this website phishing?"**

but also to explain:

> **"What did the model predict, how confident was it, which website signals were suspicious, and why was the final verdict assigned?"**

---

## 📌 Features

- 🔗 URL-based phishing detection
- 🤖 Multiple trained ML models
- 🏆 Best-model identification using **F1 Score**
- 📊 Accuracy, AUC, Precision, Recall, F1 and MCC metrics
- 📈 Phishing probability using `predict_proba()`
- 🔍 Transparent feature-level analysis
- ⚠️ Suspicious-feature detection
- 🧠 Conservative final decision logic
- 📋 Decision-threshold table in the dashboard
- 🌐 Live website/domain signal extraction
- 🔄 Redirect/final-destination inspection
- 🚫 Private/local network protection
- 📜 Recent URL analysis history
- 📚 Expandable feature-value inspection
- 🎨 Streamlit dashboard

---

# 📂 Dataset

## Phishing Websites Dataset

The project uses the **Phishing Websites** dataset from the UCI Machine Learning Repository.

**Dataset ID:** 327

**Official dataset:**

https://archive.ics.uci.edu/dataset/327/phishing

The dataset was contributed by Rami Mohammad, Lee McCluskey and Fadi Thabtah and was donated to the UCI repository in 2015. It contains **11,055 website instances and 30 integer-valued features** and is designed for a binary classification task. The dataset contains no missing values according to UCI.

The dataset was collected mainly from:

- PhishTank archives
- MillerSmiles archives
- Google search operators

The objective of the dataset is to identify characteristics that can help distinguish phishing websites from legitimate websites.

### Dataset characteristics

| Property | Value |
|---|---|
| Dataset | Phishing Websites |
| Repository | UCI Machine Learning Repository |
| Dataset ID | 327 |
| Instances | 11,055 |
| Features | 30 |
| Feature type | Integer |
| Task | Classification |
| Missing values | No |
| Domain | Computer Security |
| Target | Website classification |

---

## 🧩 Dataset Features

The dataset contains 30 website-related features.

Examples include:

| Feature | Purpose |
|---|---|
| `having_ip_address` | Checks whether an IP address is used instead of a normal domain |
| `url_length` | Evaluates URL length |
| `shortining_service` | Detects URL-shortening services |
| `having_at_symbol` | Checks for `@` in the URL |
| `double_slash_redirecting` | Detects suspicious redirection patterns |
| `prefix_suffix` | Examines prefixes/suffixes in the domain |
| `having_sub_domain` | Checks subdomain characteristics |
| `sslfinal_state` | Examines SSL/HTTPS characteristics |
| `domain_registration_length` | Examines domain registration duration |
| `favicon` | Checks favicon behavior |
| `https_token` | Examines HTTPS-related tokens |
| `request_url` | Examines external resource requests |
| `url_of_anchor` | Examines anchor URLs |
| `links_in_tags` | Examines links inside HTML tags |
| `sfh` | Server form handler characteristics |
| `submitting_to_email` | Detects forms submitting information to email |
| `abnormal_url` | Detects abnormal URL characteristics |
| `redirect` | Examines redirects |
| `on_mouseover` | Checks mouse-over behavior |
| `rightclick` | Checks right-click behavior |
| `popupwindow` | Checks popup behavior |
| `iframe` | Detects iframe usage |
| `age_of_domain` | Examines domain age |
| `dnsrecord` | Checks DNS record information |
| `web_traffic` | Examines web traffic information |
| `page_rank` | Uses page-rank-related information |
| `google_index` | Checks search engine indexing |
| `links_pointing_to_page` | Examines inbound links |
| `statistical_report` | Uses statistical/reputation information |

The official UCI variable table provides the complete feature list.

---

# 🔢 Feature Encoding

A key characteristic of this dataset is that its website features use discrete values.

The project interprets the feature signals as:

| Value | Meaning in this project |
|---:|---|
| `1` | Legitimate-like / positive signal |
| `0` | Suspicious / uncertain signal |
| `-1` | Phishing-like signal |

This is important because the application does **not simply convert all features into binary values**.

A `0` carries information and is treated as a suspicious signal.

---

# 🏗️ System Architecture

The application follows this general flow:

```text
                         USER
                          │
                          │ Enter URL
                          ▼
                  Streamlit Dashboard
                          │
                          ▼
                   URL Validation
                          │
                          ▼
              Private/Local URL Check
                          │
                          ▼
                 Live Feature Extraction
                          │
              ┌───────────┴───────────┐
              │                       │
              ▼                       ▼
       URL / Domain Signals      Page Signals
              │                       │
              └───────────┬───────────┘
                          ▼
                  Feature Vector
                          │
                          ▼
                    ML Model
                          │
              ┌───────────┴───────────┐
              │                       │
              ▼                       ▼
       model.predict()        predict_proba()
              │                       │
       Raw prediction          Phishing probability
              │                       │
              └───────────┬───────────┘
                          ▼
                 Feature Rule Engine
                          │
                          ▼
                Independent Risk Rules
                          │
                          ▼
                  Final Verdict
                          │
                          ▼
                   Streamlit UI
                          │
                          ▼
             Explanation + Evidence
```

---

# 🧠 How the Application Works

## 1. User enters a URL

The user enters a website such as:

```text
https://example.com/login
```

The application receives the URL through the Streamlit interface.

---

## 2. URL validation

The application first validates and normalizes the URL.

The system also checks whether the destination resolves to a private, loopback, link-local, reserved or multicast address.

Private/local targets are blocked by default to reduce the risk of using the application to probe internal networks.

Private URL analysis can only be enabled explicitly through:

```text
ALLOW_PRIVATE_URLS=1
```

---

# 🔍 3. Live Feature Extraction

The application extracts website characteristics from the URL, domain and page.

These signals are converted into the feature representation expected by the trained model.

Examples include:

```text
URL length
IP address usage
HTTPS characteristics
Subdomain characteristics
URL symbols
Redirect behavior
Domain information
HTML/page characteristics
DNS information
```

The goal is to recreate the feature representation used during model training as closely as possible.

---

# 🤖 4. Machine Learning Prediction

The selected trained model receives the extracted feature vector.

Two different outputs are obtained.

### Raw model prediction

The application calls:

```python
model.predict(X)
```

This produces the model's direct classification.

For example:

```text
Model prediction: PHISHING
```

or:

```text
Model prediction: LEGITIMATE
```

The UI displays this separately so that the user can see the model's literal prediction.

---

# 📊 5. Phishing Probability

The application also uses:

```python
model.predict_proba(X)
```

to obtain the estimated probability associated with the phishing class.

Example:

```text
ML phishing probability: 78.4%
```

This is different from the raw prediction.

For example, a model could produce:

```text
Model prediction: LEGITIMATE
Phishing probability: 43%
```

The application therefore does not hide the model's uncertainty.

---

# ⚖️ 6. ML Probability Decision

The application uses an intentionally lower operating threshold to make phishing detection more recall-oriented.

The current threshold is displayed in the dashboard under:

```text
Decision Thresholds
```

The dashboard shows:

| Rule | Threshold | Decision |
|---|---:|---|
| ML Phishing Probability | 35% | PHISHING |
| ML Low-Risk Boundary | 15% | LOW RISK |
| Phishing-like Features (`-1`) | ≥ 2 | PHISHING |
| Suspicious Features (`0`) | ≥ 1 | SUSPICIOUS |
| Single `-1` Feature | 1 | SUSPICIOUS |

The exact threshold values are controlled by the application's configuration and should be changed there rather than hard-coded into the Streamlit interface.

---

# 🚨 7. Feature-Based Risk Assessment

The application does not rely exclusively on the ML probability.

It separately counts feature signals.

### Phishing-like signals

A feature value of:

```text
-1
```

is considered a phishing-like signal.

The current policy is:

```text
1 × -1 → SUSPICIOUS
2+ × -1 → PHISHING
```

### Suspicious signals

A feature value of:

```text
0
```

is treated as suspicious.

Therefore:

```text
Any 0 → SUSPICIOUS
```

This allows the application to identify suspicious websites even when the ML classifier is not strongly confident.

---

# 🛡️ 8. Independent Security Rules

The application also evaluates additional security-oriented rules.

These rules are intentionally kept separate from the model prediction.

This gives the system multiple sources of evidence:

```text
ML Model
    +
ML Probability
    +
Feature Policy
    +
Independent Security Rules
    ↓
Final Verdict
```

This prevents the dashboard from misleading the user into thinking that one model output represents absolute truth.

---

# 🎯 9. Final Verdict

The final verdict is intentionally conservative.

Possible outputs are:

### 🟢 LEGITIMATE

The available evidence indicates low risk.

This does **not** mean that the website is guaranteed to be safe.

---

### 🟡 SUSPICIOUS

The application detected suspicious signals but does not have enough evidence to classify the website as clearly phishing.

Recommended action:

> Do not enter credentials or sensitive information.

---

### 🔴 PHISHING

The application has strong evidence indicating phishing behavior.

Recommended action:

> Do not open the website or enter credentials/payment information.

---

### ⚠️ INCONCLUSIVE

Too many live signals could not be collected reliably.

The application avoids incorrectly declaring the website safe when important evidence is unavailable.

---

# 🧾 Example Analysis

A result can look conceptually like:

```text
Analyzed URL:
https://example.com/account/verify

ML phishing probability:
62.4%

Model prediction:
LEGITIMATE

ML probability decision:
PHISHING

Phishing-like features (-1):
1

Suspicious features (0):
1

Feature assessment:
SUSPICIOUS

Independent rule score:
67/100

Final verdict:
SUSPICIOUS
```

This demonstrates an important property of the system:

> **Model prediction ≠ probability decision ≠ final verdict**

Each layer is displayed independently.

---

# 🏆 Model Selection

The application can contain multiple trained models.

The dashboard displays the model performance using:

- Accuracy
- AUC
- Precision
- Recall
- F1 Score
- MCC

The application identifies the **best model according to F1 Score**.

F1 is particularly useful for this application because it balances:

```text
Precision ↔ Recall
```

where:

**Precision**

> Of the websites predicted as phishing, how many were actually phishing?

**Recall**

> Of the actual phishing websites, how many did the model detect?

**F1 Score**

> A harmonic balance between precision and recall.

The dashboard displays the best-performing model at the top of the sidebar.

---

# 📊 Model Performance Dashboard

The application provides six primary evaluation metrics:

| Metric | Meaning |
|---|---|
| Accuracy | Percentage of all test samples classified correctly |
| AUC | Ability to separate phishing from legitimate websites |
| Precision | Reliability of phishing warnings |
| Recall | Percentage of phishing websites detected |
| F1 Score | Balance between precision and recall |
| MCC | Balanced correlation-based classification metric |

The application also provides a comparison table containing all trained models.

---

# 📁 Project Structure

A typical project structure is:

```text
Phishing_Link_Checker_Improved/
│
├── app.py
│
├── phishing_checker.py
│
├── requirements.txt
│
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

# 📜 Script Responsibilities

## `app.py`

`app.py` is the Streamlit presentation and application-control layer.

It handles:

- Streamlit UI
- URL input
- Model selection
- Dataset information
- Threshold display
- Model performance display
- URL validation
- Analysis execution
- Result visualization
- Recent analysis history
- Feature tables
- Explanation of final verdict

It does **not** contain the complete phishing-detection logic.

Instead, it calls the functionality implemented in:

```text
phishing_checker.py
```

---

# 🧠 `phishing_checker.py`

This is the main detection engine.

It is responsible for tasks such as:

- Loading trained models
- Resolving the selected model
- Extracting website features
- Preparing model input
- Running model prediction
- Calculating phishing probability
- Applying feature-level rules
- Applying independent security rules
- Producing the structured analysis result

The Streamlit application consumes this result and presents it to the user.

---

# 🤖 Model Artifacts

The trained models are stored inside:

```text
artifacts/
```

The application searches this directory for:

```text
*.joblib
```

Each compatible model artifact can contain information such as:

```text
Model
Features
Metrics
Training configuration
```

The application loads the available model artifacts dynamically.

Therefore, a newly trained compatible model can be added to the artifacts directory without redesigning the Streamlit interface.

---

# 📊 `tuned_results.csv`

The file:

```text
artifacts/tuned_results.csv
```

contains model-comparison results.

It is used by the dashboard to display metrics for trained models when those metrics are not already embedded inside the model artifact.

Typical columns include:

```text
Model
Accuracy
AUC
Precision
Recall
F1 Score
MCC
```

---

# 🔄 Complete Data Flow

The complete runtime data flow is:

```text
                     User URL
                        │
                        ▼
                 app.py / Streamlit
                        │
                        ▼
                 URL validation
                        │
                        ▼
             Private target protection
                        │
                        ▼
              pc.analyse(url, bundle)
                        │
                        ▼
              phishing_checker.py
                        │
                        ▼
              Feature extraction
                        │
                        ▼
                 Feature vector
                        │
          ┌─────────────┴─────────────┐
          ▼                           ▼
     ML prediction              Rule analysis
     predict()                  -1 / 0 signals
          │                           │
          ▼                           ▼
   Raw class                  Feature assessment
          │                           │
          ▼                           │
   predict_proba()                  │
          │                           │
          ▼                           ▼
 Phishing probability        Independent rules
          │                           │
          └─────────────┬─────────────┘
                        ▼
                 Decision engine
                        │
                        ▼
                  Final verdict
                        │
                        ▼
                 Result dictionary
                        │
                        ▼
                 Streamlit dashboard
                        │
        ┌───────────────┼────────────────┐
        ▼               ▼                ▼
    Probability      Features        Explanation
        │               │                │
        └───────────────┴────────────────┘
                        ▼
                   User result
```

---

# ▶️ Installation

## 1. Clone/download the project

```bash
git clone <repository-url>
cd Phishing_Link_Checker_Improved
```

Or extract the project ZIP and enter the project directory.

---

## 2. Create a virtual environment

### Linux/macOS

```bash
python -m venv .venv
source .venv/bin/activate
```

### Windows

```powershell
python -m venv .venv
.venv\Scripts\activate
```

---

## 3. Install dependencies

```bash
pip install -r requirements.txt
```

---

# ▶️ Running the Application

Start Streamlit with:

```bash
streamlit run app.py
```

Streamlit will display the local dashboard URL, normally:

```text
http://localhost:8501
```

Open that address in a browser.

---

# 🖥️ Using the Application

## Step 1 — Select a model

Use the sidebar:

```text
Model used for this check
```

The application also displays the model with the highest F1 score.

---

## Step 2 — Review the dataset

The sidebar provides information about the dataset:

```text
Phishing Websites
UCI Machine Learning Repository
```

The dataset link points to the official UCI repository:

https://archive.ics.uci.edu/dataset/327/phishing

---

## Step 3 — Review decision thresholds

The dashboard displays the application's current decision policy in tabular form.

This makes the decision system transparent before a URL is analyzed.

---

## Step 4 — Enter a URL

Enter a URL into:

```text
Website URL
```

Example:

```text
https://example.com
```

Then click:

```text
Analyze URL
```

---

# 🔎 Understanding the Result

After analysis, the application displays:

### 1. ML phishing probability

Example:

```text
73.5%
```

This represents the model's estimated probability for the phishing class.

---

### 2. Model prediction

This is the literal output of:

```python
model.predict()
```

For example:

```text
Phishing
```

---

### 3. ML probability decision

This is the classification obtained after applying the configured probability threshold.

---

### 4. Feature assessment

This is based on the extracted `-1` and `0` signals.

---

### 5. Final verdict

This is the application's combined conservative decision.

---

# 📋 Feature Evidence

The application displays suspicious feature signals in a table.

Example:

| Feature | Observed Value | Interpretation |
|---|---:|---|
| `having_ip_address` | -1 | Phishing-like signal |
| `url_length` | 0 | Suspicious signal |
| `https_token` | 1 | Legitimate-like signal |

The user can also expand:

```text
Show all feature values
```

to inspect the complete feature vector.

---

# ⚠️ Important Limitations

## 1. The model is trained on historical data

The UCI dataset represents websites and features collected for the dataset's construction.

The modern web changes continuously.

Therefore:

> High model confidence does not guarantee that a website is safe.

---

## 2. Live feature extraction can fail

Websites can:

- Block automated requests
- Require JavaScript
- Change their content
- Use anti-bot protection
- Return different content depending on location
- Become unavailable
- Change after the analysis

When important signals cannot be collected, the application can return:

```text
INCONCLUSIVE
```

rather than incorrectly claiming that the website is safe.

---

## 3. JavaScript is not executed

The application performs static analysis of retrieved page content.

It does **not** execute arbitrary JavaScript from the target website.

This limits the ability to detect phishing techniques that only appear after browser-side execution.

---

## 4. A legitimate website can still be compromised

A model may classify a website as low risk even if:

- The site has recently been compromised
- The phishing content is hidden
- The page changes after analysis
- The malicious behavior depends on browser execution

Therefore:

> **LEGITIMATE means low risk according to the available evidence, not guaranteed safe.**

---

# 🔐 Security Considerations

Never enter:

- Passwords
- Credit card information
- Banking credentials
- OTPs
- API keys
- Personal authentication information

into a website simply because this application classified it as legitimate.

The application is a **phishing-risk analysis tool**, not a security guarantee.

---

# 🧪 Testing

For testing the application, use known safe URLs or controlled test URLs.

A useful test set should contain:

```text
Legitimate URLs
        +
Suspicious URLs
        +
Phishing-pattern test URLs
```

The expected result should be compared against:

```text
Model prediction
Probability
Feature assessment
Final verdict
```

rather than only checking the final label.

---

# 🧪 Example Test Workflow

```text
Input URL
    │
    ▼
Extract features
    │
    ▼
Run trained model
    │
    ├── Prediction = 0
    └── Probability = 0.18
    │
    ▼
Evaluate feature signals
    │
    ├── -1 count = 1
    └── 0 count = 2
    │
    ▼
Feature assessment = SUSPICIOUS
    │
    ▼
Apply independent security rules
    │
    ▼
Final verdict = SUSPICIOUS
```

This demonstrates why the application provides multiple outputs instead of exposing only one classification.

---

# 📈 Why F1 Score Is Used for the Best Model

Accuracy alone can be misleading in security classification.

For example, a model could achieve high accuracy while missing a significant number of phishing websites.

Phishing detection needs to consider both:

```text
False positives
        +
False negatives
```

F1 Score provides a balance between precision and recall.

The application therefore identifies:

```text
Best Model = Model with highest F1 Score
```

while still displaying the other metrics for comparison.

---

# 📚 Project Design Philosophy

The project follows three important principles.

## 1. Transparency

Instead of showing:

```text
Result: PHISHING
```

the application explains:

```text
Model prediction
        +
Probability
        +
Feature signals
        +
Security rules
        ↓
Final verdict
```

---

## 2. Conservative security decisions

When different evidence sources disagree, the system avoids blindly trusting the most optimistic prediction.

Suspicious evidence can therefore increase the final risk classification.

---

## 3. Explainability

The application exposes the individual website signals that contributed to the decision.

This makes the system easier to demonstrate, debug and evaluate than a black-box:

```text
URL → label
```

pipeline.

---

# 📦 Main Technologies

| Technology | Purpose |
|---|---|
| Python | Core implementation |
| Streamlit | Interactive web dashboard |
| Pandas | Data processing and tables |
| Scikit-learn | Machine-learning models and metrics |
| Joblib | Model serialization |
| Requests / HTTP tooling | Live website analysis |
| UCI Dataset | Training/evaluation data |

---

# 📜 Dataset Citation

The project uses the **Phishing Websites** dataset from the UCI Machine Learning Repository.

> Mohammad, R. & McCluskey, L. (2012). *Phishing Websites* [Dataset]. UCI Machine Learning Repository. DOI: 10.24432/C51W2X.

Official repository:

https://archive.ics.uci.edu/dataset/327/phishing

The dataset is licensed under **CC BY 4.0** according to UCI.

---

# ⚖️ Disclaimer

This project is intended for:

- Educational purposes
- Machine-learning experimentation
- Phishing detection research
- Demonstration of explainable classification
- Security-awareness experimentation

It should not be treated as a replacement for:

- Browser security systems
- Enterprise security gateways
- Threat-intelligence platforms
- Antivirus/EDR systems
- Professional security analysis

A classification of **LEGITIMATE** does not guarantee that a website is safe.

---

# 🚀 Future Improvements

Potential improvements include:

- Real-time threat-intelligence integration
- URL reputation APIs
- Browser extension integration
- Screenshot-based phishing detection
- HTML/DOM deep analysis
- JavaScript behavioral analysis
- Explainable AI / SHAP visualizations
- Model monitoring
- Detection drift monitoring
- Automated model retraining
- Ensemble model predictions
- Confidence calibration
- URL history and analytics
- API deployment
- Docker deployment

---

# 👨‍💻 Project Summary

The Phishing Link Checker combines a trained machine-learning classifier with live website analysis and rule-based security checks.

The key distinction is that the system does not treat the ML model as an unquestionable authority.

Instead, it exposes:

```text
                  WEBSITE
                     │
                     ▼
             FEATURE EXTRACTION
                     │
                     ▼
             ┌───────────────┐
             │  ML MODEL     │
             └───────┬───────┘
                     │
          ┌──────────┴──────────┐
          ▼                     ▼
     Prediction            Probability
          │                     │
          └──────────┬──────────┘
                     ▼
             FEATURE POLICIES
                     │
                     ▼
             SECURITY RULES
                     │
                     ▼
               FINAL VERDICT
                     │
                     ▼
             EXPLAINABLE RESULT
```

This architecture makes the application suitable not only for predicting phishing websites, but also for demonstrating **how machine-learning predictions can be combined with transparent security rules and human-readable evidence**.