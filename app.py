import ipaddress
import os
import socket
from pathlib import Path
from urllib.parse import urlparse

import pandas as pd
import streamlit as st

st.set_page_config(page_title="Phishing Link Checker", page_icon="🛡️", layout="wide")

try:
    import phishing_checker as pc
except ImportError:
    st.error("phishing_checker.py must be in the same folder as app.py.")
    st.stop()

ART = Path("artifacts")
METRIC_NAMES = ["Accuracy", "AUC", "Precision", "Recall", "F1 Score", "MCC"]
METRIC_HELP = {
    "Accuracy": "Share of all test websites classified correctly.",
    "AUC": "How well the model separates phishing from legitimate websites.",
    "Precision": "Of links flagged as phishing, how many were actually phishing.",
    "Recall": "Of all phishing links, how many the model detected.",
    "F1 Score": "Balance between phishing precision and recall.",
    "MCC": "Balanced quality score from -1 to +1; 1 is perfect."
}

def is_private_target(url):
    host = urlparse(url if "://" in url else "https://" + url).hostname
    if not host:
        return False
    try:
        addresses = [ipaddress.ip_address(host.strip("[]"))]
    except ValueError:
        try:
            addresses = [ipaddress.ip_address(x[4][0]) for x in socket.getaddrinfo(host, None)]
        except OSError:
            return False
    return any(a.is_private or a.is_loopback or a.is_link_local or a.is_reserved or a.is_multicast
               for a in addresses)

@st.cache_resource
def load_models(signature):
    models = {}
    for path, _mtime in signature:
        try:
            models[path] = pc.load_model(path)
        except Exception:
            continue
    return models

def display_name(path):
    name = Path(path).stem.replace("_tuned", "").replace("_", " ").title()
    return name.replace("Svm", "SVM").replace("Knn", "KNN")

def metric_value(metrics, key):
    value = metrics.get(key)
    return "—" if value is None else f"{float(value):.3f}"

st.title("🛡️ Phishing Link Checker")
st.caption("Analyze a URL using a trained machine-learning model and inspect the signals behind its prediction.")

signature = tuple((str(p), p.stat().st_mtime) for p in sorted(ART.glob("*.joblib"))) if ART.exists() else ()
loaded = load_models(signature) if signature else {}
if not loaded:
    st.error("No compatible model artifacts found. Run the training notebook and save models in ./artifacts.")
    st.stop()

paths = list(loaded)
default_path = str(pc.resolve_model_path(None))
default_idx = next((i for i, p in enumerate(paths)
                    if Path(p).resolve() == Path(default_path).resolve()), 0)

with st.sidebar:
    st.header("Model")
    selected_path = st.selectbox("Model used for this check", paths, index=default_idx,
                                 format_func=display_name)
    bundle = loaded[selected_path]
    st.caption(f"{len(bundle['features'])} live-aligned features")
    st.divider()
    st.markdown("**Decision Thresholds**")

    threshold_df = pd.DataFrame({
        "Rule": [
            "ML Phishing Probability",
            "ML Low-Risk Boundary",
            "Phishing-like Features (-1)",
            "Suspicious Features (0)",
            "Single -1 Feature"
        ],
        "Threshold": [
            f"{pc.PHISH_THRESHOLD:.0%}",
            f"{pc.LEGIT_THRESHOLD:.0%}",
            "≥ 2",
            "≥ 1",
            "1"
        ],
        "Decision": [
            "PHISHING",
            "LOW RISK",
            "PHISHING",
            "SUSPICIOUS",
            "SUSPICIOUS"
        ]
    })

    st.table(threshold_df)

    st.caption(
        "Final verdict uses the most conservative result from the ML probability, "
        "feature policy, and independent security rules."
    )
    st.caption("The model prediction and probability are shown separately from the final combined verdict.")
    st.caption("Missing critical live signals can make the result inconclusive.")

st.subheader("Model performance")
metrics = bundle.get("metrics", {})
if not metrics:
    try:
        perf = pd.read_csv(ART / "tuned_results.csv").set_index("Model")
        metrics = perf.loc[bundle["name"]].to_dict()
    except Exception:
        metrics = {}

metric_cols = st.columns(6)
for col, key in zip(metric_cols, METRIC_NAMES):
    col.metric(key, metric_value(metrics, key), help=METRIC_HELP[key])

with st.expander("Compare all trained models", expanded=False):
    try:
        comparison = pd.read_csv(ART / "tuned_results.csv")
        keep = [c for c in ["Model"] + METRIC_NAMES if c in comparison.columns]
        st.dataframe(comparison[keep].style.format({c: "{:.3f}" for c in METRIC_NAMES
                                                    if c in keep}),
                     use_container_width=True, hide_index=True)
        st.caption("Metrics are measured on the held-out test set. Recall is the share of phishing links caught.")
    except Exception:
        st.info("Run the notebook to generate tuned_results.csv.")

st.divider()
st.subheader("Check a website")
with st.form("url_check", clear_on_submit=False):
    url = st.text_input("Website URL", placeholder="https://example.com/login")
    submitted = st.form_submit_button("Analyze URL", type="primary", use_container_width=True)

if submitted:
    st.session_state.pop("last_result", None)
    if not url.strip():
        st.warning("Enter a URL to analyze.")
    elif is_private_target(url) and os.environ.get("ALLOW_PRIVATE_URLS") != "1":
        st.error("This address points to a private or local network and cannot be checked.")
    else:
        try:
            with st.spinner("Collecting URL, domain and page signals…"):
                result = pc.analyse(url, bundle)
            st.session_state["last_result"] = result
            history = st.session_state.setdefault("history", [])
            history.insert(0, {"URL": result["url"][:70], "Verdict": result["verdict"]})
            del history[10:]
        except ValueError as exc:
            st.error(f"Invalid URL: {exc}")
        except Exception as exc:
            st.error(f"Could not analyze this URL: {exc}")

# result = st.session_state.get("last_result")
# if result:
#     st.divider()
#     verdict = result["verdict"]
#     probability = result["phishing_probability"]
#     if verdict == "PHISHING":
#         st.error("🚫 High risk — likely phishing. Do not open or enter information.")
#     elif verdict == "SUSPICIOUS":
#         st.warning("⚠️ Suspicious link — multiple risk signals were detected. Do not enter credentials.")
#     elif verdict == "LEGITIMATE":
#         st.success("✅ Low risk based on the signals available. This is not a safety guarantee.")
#     else:
#         st.warning("⚠️ Inconclusive — too many live signals could not be measured. Do not assume this link is safe.")

#     st.write("**Analyzed URL**")
#     st.code(result["url"])
#     if result["info"].get("final_url") and result["info"]["final_url"] != result["url"]:
#         st.write("**Final destination after redirects**")
#         st.code(result["info"]["final_url"])

#     if probability is not None:
#         c1, c2, c3, c4 = st.columns(4)
#         c1.metric("ML phishing probability", f"{probability:.1%}")
#         c2.metric("Model prediction", result.get("raw_model_verdict", "—").title())
#         c3.metric("ML probability decision", result.get("model_probability_verdict", "—").title())
#         c4.metric("Final verdict", verdict.title())
#         st.progress(min(max(float(probability), 0.0), 1.0),
#                     text=f"Model-estimated phishing probability · {probability:.1%}")

#         fc1, fc2, fc3 = st.columns(3)
#         fc1.metric("Phishing-like (-1)", result.get("phishing_like_count", 0))
#         fc2.metric("Suspicious (0)", result.get("suspicious_feature_count", 0))
#         fc3.metric("Feature assessment", result.get("feature_verdict", "—").replace("_", " ").title())
#         st.caption(
#             f"Estimator predict(): {result.get('raw_model_verdict', '—')} · "
#             f"Probability decision at {pc.DECISION_THRESHOLD:.0%}: {result.get('model_probability_verdict', '—')} · "
#             f"Feature decision: {result.get('feature_verdict', '—')} · "
#             f"Independent rule score: {result.get('risk_score', 0)}/100 · "
#             f"Unavailable live signals: {len(result['unavailable_features'])}"
#         )

#     st.subheader("Decision breakdown")
#     st.info(
#         f"**Model prediction:** {result.get('raw_model_verdict', '—')} "
#         f"(class {result.get('raw_model_prediction', '—')}).  "
#         f"**Phishing probability:** {('N/A' if probability is None else f'{probability:.1%}')}  "
#         f"**Feature assessment:** {result.get('feature_verdict', '—')}. "
#         "The final verdict is the most conservative result of the model probability, "
#         "live-feature policy, and independent security rules."
#     )

#     st.subheader("Why this verdict was assigned")
#     if result.get("rule_reasons"):
#         st.dataframe(pd.DataFrame(result["rule_reasons"]), use_container_width=True, hide_index=True)
#     else:
#         st.write("No additional rule-based risk indicators were found.")

#     st.subheader("Live model feature signals")
#     if result["red_flags"]:
#         flag_rows = [{"Feature": item["feature"], "Observed value": item["value"],
#                       "Interpretation": item["meaning"]} for item in result["red_flags"]]
#         st.dataframe(pd.DataFrame(flag_rows), use_container_width=True, hide_index=True)
#     else:
#         st.write("No -1 or 0 feature signals were returned by the live feature checks.")

#     if result["unavailable_features"]:
#         st.info("Could not measure: " + ", ".join(result["unavailable_features"]))
#     with st.expander("Show all feature values"):
#         rows = [{"Feature": feature,
#                  "Value": ("Unavailable" if value is None else value),
#                  "Meaning": pc.DESCRIPTIONS.get(feature, "Live website signal")}
#                 for feature, value in result["features"].items()]
#         st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)

# st.divider()
# with st.expander("Recent checks"):
#     history = st.session_state.get("history", [])
#     if history:
#         st.dataframe(pd.DataFrame(history), use_container_width=True, hide_index=True)
#     else:
#         st.caption("No checks yet.")

# with st.expander("How to interpret the result"):
#     st.markdown("""
#     - **Model prediction** is the classifier's literal `predict()` result: class `1` = Phishing and class `0` = Legitimate.
#     - **ML phishing probability** is the selected model's `predict_proba()` estimate for class `1`. The UI uses the lower 35% operating threshold to make the probability decision more recall-oriented.
#     - **Feature policy:** `-1` is phishing-like and `0` is suspicious. One `-1` or any `0` makes the feature assessment suspicious; **two or more `-1` values make it phishing**.
#     - The **final verdict** is intentionally conservative: strong model probability or phishing-like feature evidence can raise the result to phishing, while suspicious evidence raises it to suspicious.
#     - **Low risk** never means guaranteed safe.
#     - **Recall** measures how many phishing websites in the held-out test set were caught. For security screening, this is especially important.
#     - **Precision** measures how often a phishing warning is correct.
#     - **AUC** measures ranking/separation ability; **F1** balances precision and recall; **MCC** is a balanced correlation score.
#     - A model prediction is not proof that a website is safe. The training dataset is historical, and live pages may block automated checks or change after analysis.
#     - The page is fetched for static HTML analysis; JavaScript is not executed. Never submit passwords or payment information to a link you do not trust.
#     """)
