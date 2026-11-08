import argparse
import concurrent.futures as cf
import csv
import ipaddress
import json
import re
import socket
import ssl
import sys
import warnings
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urljoin, urlparse, parse_qs, unquote

import joblib
import numpy as np
import pandas as pd
import requests
import tldextract
from bs4 import BeautifulSoup

warnings.filterwarnings("ignore")
requests.packages.urllib3.disable_warnings()  ## for displaying bad warnings

RANDOM_STATE = 42
TIMEOUT = 8                      # seconds per network call
MAX_BYTES = 2_000_000            # never download more than 2 MB of a page
UA = "Mozilla/5.0 (compatible; PhishingChecker/1.0)"
DEFAULT_MODEL_PATH = Path("artifacts/live_phishing_model.joblib")
# Decision policy
# 1) The trained model remains the primary ML signal and its probability is shown.
# 2) The live UCI feature values are also counted explicitly:
#       -1 = phishing-like, 0 = suspicious, 1 = legitimate-like
#    One -1 OR any 0 makes the feature assessment suspicious.
#    Two or more -1 values makes the feature assessment phishing.
# 3) The lower ML probability threshold is intentionally recall-oriented.
DECISION_THRESHOLD = 0.35
PHISH_THRESHOLD = DECISION_THRESHOLD
LEGIT_THRESHOLD = 0.15
FEATURE_PHISHING_NEGATIVES = 2
FEATURE_SUSPICIOUS_NEGATIVES = 1
FEATURE_SUSPICIOUS_ZEROS = 1
SUSPICIOUS_RISK_THRESHOLD = 30
PHISHING_RISK_THRESHOLD = 60
MAX_MISSING = 5                  # more unavailable live features than this -> INCONCLUSIVE

ALL_FEATURES = [
    "having_IP_Address", "URL_Length", "Shortining_Service", "having_At_Symbol",
    "double_slash_redirecting", "Prefix_Suffix", "having_Sub_Domain", "SSLfinal_State",
    "Domain_registeration_length", "Favicon", "port", "HTTPS_token", "Request_URL",
    "URL_of_Anchor", "Links_in_tags", "SFH", "Submitting_to_email", "Abnormal_URL",
    "Redirect", "on_mouseover", "RightClick", "popUpWidnow", "Iframe", "age_of_domain",
    "DNSRecord", "web_traffic", "Page_Rank", "Google_Index", "Links_pointing_to_page",
    "Statistical_report",
]

UNOBTAINABLE = ["web_traffic", "Page_Rank", "Google_Index", "Links_pointing_to_page", "Statistical_report"]

DESCRIPTIONS = {
    "having_IP_Address": "URL uses a raw IP address instead of a domain name",
    "URL_Length": "URL is unusually long",
    "Shortining_Service": "URL uses a link-shortening service",
    "having_At_Symbol": "URL contains '@' (browser ignores everything before it)",
    "double_slash_redirecting": "'//' appears inside the URL path (redirect trick)",
    "Prefix_Suffix": "domain name contains '-' (common in look-alike domains)",
    "having_Sub_Domain": "many sub-domains",
    "SSLfinal_State": "no valid HTTPS certificate",
    "Domain_registeration_length": "domain registration expires within a year",
    "Favicon": "favicon loaded from a different domain",
    "port": "non-standard port in URL",
    "HTTPS_token": "the word 'https' is faked inside the domain name",
    "Request_URL": "many images/media are loaded from other domains",
    "URL_of_Anchor": "many links point to other domains or to nowhere ('#')",
    "Links_in_tags": "many script/meta/link resources come from other domains",
    "SFH": "form submits to a blank or different domain",
    "Submitting_to_email": "form submits data to an e-mail address",
    "Abnormal_URL": "registered domain does not match the URL host",
    "Redirect": "multiple redirects before the final page",
    "on_mouseover": "script alters the status bar on mouse-over",
    "RightClick": "right-click is disabled",
    "popUpWidnow": "page opens pop-up windows from inline script",
    "Iframe": "hidden iframe on the page",
    "age_of_domain": "domain is younger than 6 months",
    "DNSRecord": "domain has no DNS record",
}

# Common URL shorteners
SHORTENERS = {
    "bit.ly", "bitly.com", "goo.gl", "tinyurl.com", "ow.ly", "t.co", "is.gd", "buff.ly", "adf.ly",
    "bit.do", "cutt.ly", "rebrand.ly", "shorturl.at", "tiny.cc", "lnkd.in", "v.gd", "rb.gy", "t.ly",
    "trib.al", "mcaf.ee", "su.pr", "po.st", "qr.net", "x.co", "j.mp", "tr.im", "cli.gs", "yfrog.com",
    "migre.me", "ff.im", "tiny.pl", "url4.eu", "twit.ac", "twurl.nl", "snipurl.com", "short.to",
    "budurl.com", "ping.fm", "post.ly", "just.as", "bkite.com", "snipr.com", "fic.kr", "loopt.us",
    "doiop.com", "short.ie", "kl.am", "wp.me", "u.to", "cur.lv", "ity.im", "q.gs", "tinyarro.ws",
    "link.zip", "shorte.st", "bc.vc", "soo.gd", "clck.ru", "s.id", "urlz.fr", "lc.chat",
}

_tld = tldextract.TLDExtract(suffix_list_urls=())


# Helper functions to detect features
def normalize_url(raw: str) -> str:
    u = raw.strip().strip("'\"<>")
    if not u:
        raise ValueError("Empty URL.")
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.\-]*://", u):
        u = "https://" + u
    p = urlparse(u)
    if p.scheme not in ("http", "https"):
        raise ValueError(f"Only http/https URLs are supported (got '{p.scheme}').")
    if not p.hostname:
        raise ValueError("Could not find a host name in the URL.")
    return u


def is_ip_host(host: str) -> bool:
    h = host.strip("[]")
    try:
        ipaddress.ip_address(h)
        return True
    except ValueError:
        pass
    return bool(re.fullmatch(r"0x[0-9a-fA-F]+", h) or re.fullmatch(r"\d{8,10}", h))


def host_key(url: str) -> str:
    """Comparable 'owner' of a URL: registered domain (or the IP)."""
    host = (urlparse(url).hostname or "").lower()
    if is_ip_host(host):
        return host
    ext = _tld(host)
    return (ext.top_domain_under_public_suffix if hasattr(ext, "top_domain_under_public_suffix")
            else ext.registered_domain) or host


def pct_to_score(pct: float, low: float, high: float) -> int:
    """<low -> 1 (legit), low..high -> 0 (suspicious), >high -> -1 (phishing)"""
    if pct < low:
        return 1
    return 0 if pct <= high else -1


def parse_date(s):
    if not s:
        return None
    try:
        d = datetime.fromisoformat(s.replace("Z", "+00:00"))
    except ValueError:
        try:
            d = datetime.fromisoformat(s[:19])
        except ValueError:
            return None
    return d if d.tzinfo else d.replace(tzinfo=timezone.utc)


def fetch_page(url: str):
    """Download the page (no JavaScript). Returns (response, html) or (None, None)."""
    headers = {"User-Agent": UA, "Accept": "text/html,*/*;q=0.8"}
    for verify in (True, False):
        try:
            r = requests.get(url, headers=headers, timeout=TIMEOUT, allow_redirects=True,
                             stream=True, verify=verify)
            chunks, size = [], 0
            for chunk in r.iter_content(65536):
                chunks.append(chunk)
                size += len(chunk)
                if size > MAX_BYTES:
                    break
            r.close()
            html = b"".join(chunks).decode(r.encoding or "utf-8", errors="replace")
            return r, html
        except requests.exceptions.SSLError:
            continue                      # retry once without verification so we can still read the page
        except requests.RequestException:
            return None, None
    return None, None


def rdap_lookup(domain: str):
    """Registration / expiry dates via RDAP. Returns dict or None if unavailable."""
    try:
        r = requests.get(f"https://rdap.org/domain/{domain}", timeout=TIMEOUT,
                         headers={"Accept": "application/rdap+json", "User-Agent": UA})
        if r.status_code != 200:
            return None
        data = r.json()
    except (requests.RequestException, ValueError):
        return None
    events = {e.get("eventAction"): e.get("eventDate") for e in data.get("events", [])}
    return {
        "name": (data.get("ldhName") or "").lower(),
        "registered": parse_date(events.get("registration")),
        "expires": parse_date(events.get("expiration")),
    }


def dns_state(host: str):
    """1 = resolves, -1 = definitely does not exist, None = could not tell (e.g. offline)."""
    try:
        socket.getaddrinfo(host, None)
        return 1
    except socket.gaierror as e:
        return -1 if e.errno == socket.EAI_NONAME else None
    except OSError:
        return None


def ssl_state(url: str):
    """1 = valid verified certificate, 0 = HTTPS but certificate fails verification,
    -1 = plain HTTP, None = could not tell."""
    p = urlparse(url)
    if p.scheme != "https":
        return -1
    port = p.port or 443
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((p.hostname, port), timeout=TIMEOUT) as s:
            with ctx.wrap_socket(s, server_hostname=p.hostname):
                return 1
    except ssl.SSLCertVerificationError:
        return 0
    except ssl.SSLError:
        return 0
    except OSError:
        return None


def url_features(url: str) -> dict:
    p = urlparse(url)
    host = (p.hostname or "").lower()
    ext = _tld(host)
    ip = is_ip_host(host)
    f = {}

    f["having_IP_Address"] = -1 if ip else 1

    n = len(url)
    f["URL_Length"] = 1 if n < 54 else (0 if n <= 75 else -1)

    reg = ext.top_domain_under_public_suffix if hasattr(ext, "top_domain_under_public_suffix") else ext.registered_domain
    f["Shortining_Service"] = -1 if (host in SHORTENERS or reg in SHORTENERS) else 1

    f["having_At_Symbol"] = -1 if "@" in url else 1
    # UCI signal refers to // inside the URL path, not the mandatory :// scheme
    # delimiter or an URL embedded in a query parameter.
    f["double_slash_redirecting"] = -1 if "//" in (p.path or "") else 1
    f["Prefix_Suffix"] = -1 if "-" in host else 1

    if ip:
        f["having_Sub_Domain"] = 1
    else:
        sub = [x for x in ext.subdomain.split(".") if x and x != "www"]
        f["having_Sub_Domain"] = 1 if len(sub) == 0 else (0 if len(sub) == 1 else -1)

    f["port"] = -1 if (p.port not in (None, 80, 443)) else 1
    f["HTTPS_token"] = -1 if "https" in host else 1
    return f


def html_features(html: str, final_url: str, n_redirects: int) -> dict:
    """Features that come from the downloaded page. Every value is computed or None."""
    soup = BeautifulSoup(html, "html.parser")
    own = host_key(final_url)
    low = html.lower()
    f = {}

    def external(v):
        a = urljoin(final_url, v.strip())
        if urlparse(a).scheme not in ("http", "https"):
            return None            # not a web link -> ignore
        return host_key(a) != own

    # Favicon
    icons = [l.get("href") for l in soup.find_all("link", rel=True)
             if "icon" in " ".join(l["rel"]).lower() and l.get("href")]
    f["Favicon"] = -1 if any(external(h) for h in icons) else 1

    # Request_URL  (<img>, <video>, <audio>, <embed>, <source>)
    objs = [t.get("src") for t in soup.find_all(["img", "video", "audio", "embed", "source"]) if t.get("src")]
    flags = [external(o) for o in objs]
    flags = [x for x in flags if x is not None]
    f["Request_URL"] = pct_to_score(100 * sum(flags) / len(flags) if flags else 0, 22, 61)

    # URL_of_Anchor
    anchors = [a.get("href", "").strip() for a in soup.find_all("a", href=True)]
    bad = tot = 0
    for h in anchors:
        hl = h.lower()
        if hl.startswith(("mailto:", "tel:")):
            continue
        tot += 1
        if hl in ("", "#") or hl.startswith(("#", "javascript")) or external(h):
            bad += 1
    f["URL_of_Anchor"] = pct_to_score(100 * bad / tot if tot else 0, 31, 67)

    # Links_in_tags  (<script src>, <link href>, <meta content=http...>)
    refs = [t.get("src") for t in soup.find_all("script") if t.get("src")]
    refs += [t.get("href") for t in soup.find_all("link") if t.get("href")]
    refs += [t.get("content") for t in soup.find_all("meta")
             if t.get("content") and re.match(r"^https?://", t["content"].strip(), re.I)]
    flags = [x for x in (external(r) for r in refs) if x is not None]
    f["Links_in_tags"] = pct_to_score(100 * sum(flags) / len(flags) if flags else 0, 17, 81)

    # SFH + Submitting_to_email  (look at every <form>)
    sfh, mail = 1, 1
    for form in soup.find_all("form"):
        act = (form.get("action") or "").strip()
        al = act.lower()
        if al.startswith("mailto:"):
            mail = -1
        if al in ("", "about:blank"):
            sfh = -1
        elif external(act):
            sfh = min(sfh, 0)
    f["SFH"], f["Submitting_to_email"] = sfh, mail

    # Redirect
    f["Redirect"] = 1 if n_redirects <= 1 else (0 if n_redirects <= 4 else -1)

    # Script behaviours
    f["on_mouseover"] = -1 if re.search(r"onmouseover\s*=\s*[\"'][^\"']*(window\.status|status\s*=)", low) else 1
    f["RightClick"] = -1 if (re.search(r"event\.button\s*={1,3}\s*2", low) or
                             re.search(r"oncontextmenu\s*=\s*[\"']?\s*return\s+false", low)) else 1
    inline_js = " ".join(s.get_text() for s in soup.find_all("script") if not s.get("src")).lower()
    f["popUpWidnow"] = -1 if "window.open(" in inline_js else 1

    hidden = False
    for fr in soup.find_all(["iframe", "frame"]):
        style = (fr.get("style") or "").lower().replace(" ", "")
        w, h = (fr.get("width") or "").strip().lower(), (fr.get("height") or "").strip().lower()
        zero = lambda v: v in ("0", "0px", "0%")
        if "display:none" in style or "visibility:hidden" in style or zero(w) or zero(h):
            hidden = True
    f["Iframe"] = -1 if hidden else 1
    return f


def domain_features(host: str, rdap, dns, ssl_val) -> dict:
    now = datetime.now(timezone.utc)
    f = {"DNSRecord": dns, "SSLfinal_State": ssl_val,
         "age_of_domain": None, "Domain_registeration_length": None, "Abnormal_URL": None}
    if rdap:
        if rdap["registered"]:
            f["age_of_domain"] = 1 if (now - rdap["registered"]).days >= 180 else -1
        if rdap["expires"]:
            f["Domain_registeration_length"] = -1 if (rdap["expires"] - now).days <= 365 else 1
        reg = host_key("http://" + host)
        if rdap["name"]:
            f["Abnormal_URL"] = 1 if rdap["name"] == reg else -1
    return f


# Extracting Features through Helper functions
def extract_features(url: str):
    """Returns (features: {name: -1/0/1/None}, info: dict). None = could not be measured."""
    url = normalize_url(url)
    host = urlparse(url).hostname.lower()
    ip = is_ip_host(host)
    reg = None if ip else host_key(url)

    feats = {k: None for k in ALL_FEATURES}
    feats.update(url_features(url))

    with cf.ThreadPoolExecutor(max_workers=4) as ex:
        t_page = ex.submit(fetch_page, url)
        t_rdap = ex.submit(rdap_lookup, reg) if reg else None
        t_dns = ex.submit(dns_state, host)
        t_ssl = ex.submit(ssl_state, url)
        resp, html = t_page.result()
        rdap = t_rdap.result() if t_rdap else None
        dns, ssl_val = t_dns.result(), t_ssl.result()

    feats.update(domain_features(host, rdap, dns, ssl_val))

    info = {"url": url, "page_fetched": resp is not None, "final_url": url, "redirects": 0,
            "http_status": None, "rdap_found": rdap is not None}
    if resp is not None:
        info.update(final_url=resp.url, redirects=len(resp.history), http_status=resp.status_code)
        feats.update(html_features(html, resp.url, len(resp.history)))
    return feats, info


# --------------------------------------------------------------------------- feature-name matching
def _norm(name: str) -> str:
    return re.sub(r"[^a-z0-9]", "", str(name).lower())


_ALIASES = {
    "domainregistrationlength": "Domain_registeration_length",
    "popupwindow": "popUpWidnow",
    "popupwidnow": "popUpWidnow",
    "shorteningservice": "Shortining_Service",
    "ipaddress": "having_IP_Address",
    "havingipaddress": "having_IP_Address",
}
CANON = {_norm(f): f for f in ALL_FEATURES}
CANON.update(_ALIASES)


def canonical_feature(name):
    """Map a model's column name (any case / spelling variant) to the script's feature name."""
    return CANON.get(_norm(name))


# Loading model from local path
def resolve_model_path(arg):
    if arg:
        return Path(arg)
    meta = Path("artifacts/best_model.json")
    if meta.exists():
        try:
            name = json.loads(meta.read_text()).get("model", "")
            cand = Path("artifacts") / (name.lower().replace(" ", "_") + "_tuned.joblib")
            if cand.exists():
                return cand
        except (ValueError, OSError):
            pass
    return DEFAULT_MODEL_PATH


def load_model(path):
    """Load a joblib file: either a plain sklearn estimator/pipeline (as saved by the notebook)
    or a dict bundle {'model': ..., 'features': [...]}."""
    path = Path(path)
    if not path.exists():
        sys.exit(f"Model file not found: {path}\nPass one with --model PATH.")
    obj = joblib.load(path)

    if isinstance(obj, dict) and "model" in obj:
        model, name = obj["model"], obj.get("name", path.stem)
        feats = list(obj.get("features") or getattr(model, "feature_names_in_", []))
    else:
        model, name = obj, path.stem
        feats = getattr(model, "feature_names_in_", None)
        if feats is None:
            if getattr(model, "n_features_in_", None) == len(ALL_FEATURES):
                feats = ALL_FEATURES
            else:
                sys.exit("Cannot tell which features this model expects. Re-save it from a DataFrame "
                         "or wrap it as {'model': model, 'features': [...]}.")
        feats = list(feats)

    model_cols = list(feats)                                    # names exactly as the model saw them
    canon = [canonical_feature(f) for f in model_cols]
    unknown = [m for m, c in zip(model_cols, canon) if c is None]
    if unknown or not model_cols:
        sys.exit(f"Model expects unrecognised features: {unknown}")
    if len(set(canon)) != len(canon):
        sys.exit("Model has duplicate features after name matching.")
    feats = canon
    if not (hasattr(model, "predict_proba") or hasattr(model, "predict")):
        sys.exit("Loaded object is not a classifier.")

    has_imputer = hasattr(model, "named_steps") and "imputer" in model.named_steps
    return {"model": model, "features": feats, "model_cols": model_cols, "name": name,
            "has_imputer": has_imputer, "metrics": (obj.get("metrics", {}) if isinstance(obj, dict) else {}),
            "path": str(path)}


REDIRECT_KEYS = {"url", "u", "target", "dest", "destination", "redirect",
                 "redirect_url", "redirect_uri", "return", "return_to", "next", "continue"}

def _external_redirect_target(url: str):
    """Return an external URL found in a redirect-like query parameter, if any."""
    p = urlparse(url)
    own = host_key(url)
    for key, values in parse_qs(p.query, keep_blank_values=False).items():
        if key.lower() not in REDIRECT_KEYS:
            continue
        for value in values:
            candidate = unquote(value).strip()
            if candidate.startswith(("http://", "https://", "//")):
                absolute = urljoin(url, candidate)
                if urlparse(absolute).hostname and host_key(absolute) != own:
                    return absolute
    return None

def assess_rule_risk(url: str, feats: dict, info: dict):
    """Heuristic risk score; deliberately separate from the ML probability."""
    score, reasons = 0, []
    def add(points, reason):
        nonlocal score
        score += points
        reasons.append({"points": points, "reason": reason})

    p = urlparse(url)
    host = (p.hostname or "").lower()
    external_target = _external_redirect_target(url)
    if external_target:
        add(40, f"Redirect parameter points to a different registered domain: {external_target}")
    if "//" in (p.path or ""):
        add(20, "Double slash appears inside the URL path")
    if feats.get("having_At_Symbol") == -1:
        add(25, "URL contains @, which can disguise the actual host")
    if feats.get("having_IP_Address") == -1:
        add(20, "URL uses an IP address instead of a domain")
    if feats.get("Shortining_Service") == -1:
        add(12, "URL uses a known link-shortening service")
    if feats.get("HTTPS_token") == -1:
        add(20, "The hostname contains the misleading token 'https'")
    if feats.get("Prefix_Suffix") == -1:
        add(5, "Hostname contains a hyphen")
    if feats.get("having_Sub_Domain") == -1:
        add(8, "Hostname has multiple subdomains")
    if feats.get("URL_Length") == -1:
        add(5, "URL is unusually long")
    if feats.get("SSLfinal_State") == -1:
        add(8, "URL uses HTTP rather than HTTPS")
    if feats.get("SSLfinal_State") == 0:
        add(12, "HTTPS certificate could not be validated")
    if feats.get("Domain_registeration_length") == -1:
        add(8, "Domain registration expires within one year")
    if feats.get("age_of_domain") == -1:
        add(12, "Domain is less than six months old")
    if feats.get("DNSRecord") == -1:
        add(20, "Hostname has no DNS record")
    if feats.get("SFH") in (-1, 0):
        add(20, "Page form submits to a blank or different domain")
    if feats.get("Submitting_to_email") == -1:
        add(25, "Page form submits information to an email address")
    if feats.get("Abnormal_URL") == -1:
        add(20, "Registration identity does not match the URL host")
    if feats.get("Redirect") == -1:
        add(15, "Page followed an unusually large number of redirects")

    score = min(score, 100)
    if score >= PHISHING_RISK_THRESHOLD:
        verdict = "PHISHING"
    elif score >= SUSPICIOUS_RISK_THRESHOLD:
        verdict = "SUSPICIOUS"
    else:
        verdict = "LOW_RISK"
    return score, verdict, reasons

# Predicting results
def analyse(url: str, bundle) -> dict:
    feats, info = extract_features(url)
    cols, model = bundle["features"], bundle["model"]

    # Models with an imputer handle NaN themselves. Plain models (notebook) cannot, so features that
    # could not be measured are set to 0 = "suspicious / neutral" in the UCI coding.
    fill = np.nan if bundle["has_imputer"] else 0
    row = pd.DataFrame([{mc: (fill if feats[c] is None else feats[c])
                         for mc, c in zip(bundle["model_cols"], cols)}])[bundle["model_cols"]]
    missing = [c for c in cols if feats[c] is None]
    measurable_missing = [c for c in missing if c not in UNOBTAINABLE]   # genuine failures

    # IMPORTANT: keep the estimator's own prediction separate from our lower probability
    # operating threshold. This lets the UI show both the literal model.predict() result
    # and the recall-oriented probability decision.
    raw_prediction = int(model.predict(row)[0])
    raw_ml_verdict = "PHISHING" if raw_prediction == 1 else "LEGITIMATE"

    if hasattr(model, "predict_proba"):
        classes = list(model.classes_)
        if 1 not in classes:
            raise ValueError(f"Model classes {classes} do not contain phishing class 1.")
        p = float(model.predict_proba(row)[0, classes.index(1)])
        probability_ml_verdict = "PHISHING" if p >= DECISION_THRESHOLD else (
            "SUSPICIOUS" if p > LEGIT_THRESHOLD else "LEGITIMATE")
    else:
        p = None
        probability_ml_verdict = raw_ml_verdict

    # Explicit live-feature policy requested for the checker:
    #   >=2 values of -1  -> PHISHING
    #   exactly 1 value -1 OR >=1 value 0 -> SUSPICIOUS
    #   otherwise          -> LOW_RISK
    phishing_like_count = sum(v == -1 for v in feats.values() if v is not None)
    suspicious_count = sum(v == 0 for v in feats.values() if v is not None)
    if phishing_like_count >= FEATURE_PHISHING_NEGATIVES:
        feature_verdict = "PHISHING"
    elif phishing_like_count >= FEATURE_SUSPICIOUS_NEGATIVES or suspicious_count >= FEATURE_SUSPICIOUS_ZEROS:
        feature_verdict = "SUSPICIOUS"
    else:
        feature_verdict = "LOW_RISK"

    risk_score, risk_verdict, rule_reasons = assess_rule_risk(info["url"], feats, info)

    # Final verdict combines the model probability with the explicit feature policy.
    # The model is always visible separately; feature evidence can only increase the
    # risk classification, never make a phishing model prediction look safer.
    if len(measurable_missing) > MAX_MISSING:
        verdict = "INCONCLUSIVE"
    elif feature_verdict == "PHISHING" or risk_verdict == "PHISHING" or (
            p is not None and p >= PHISH_THRESHOLD):
        verdict = "PHISHING"
    elif feature_verdict == "SUSPICIOUS" or risk_verdict == "SUSPICIOUS" or (
            p is not None and p > LEGIT_THRESHOLD):
        verdict = "SUSPICIOUS"
    else:
        verdict = "LEGITIMATE"

    flags = [{"feature": c, "value": feats[c], "meaning": DESCRIPTIONS.get(c, c)}
             for c in cols if feats[c] in (-1, 0) and feats[c] is not None]
    return {"url": info["url"], "verdict": verdict,
            "phishing_probability": None if p is None else round(p, 4),
            "raw_model_prediction": raw_prediction,
            "raw_model_verdict": raw_ml_verdict,
            "ml_verdict": probability_ml_verdict,
            "model_probability_verdict": probability_ml_verdict,
            "feature_verdict": feature_verdict,
            "phishing_like_count": phishing_like_count,
            "suspicious_feature_count": suspicious_count,
            "risk_score": risk_score, "risk_verdict": risk_verdict,
            "rule_reasons": rule_reasons,
            "unavailable_features": missing,
            "set_to_neutral_0": [] if bundle["has_imputer"] else missing,
            "red_flags": flags, "features": {c: feats[c] for c in cols}, "info": info}


def print_report(r: dict):
    icon = {"PHISHING": "[!!]", "SUSPICIOUS": "[! ]", "LEGITIMATE": "[ok]", "INCONCLUSIVE": "[??]"}[r["verdict"]]
    p = r["phishing_probability"]
    print("\n" + "=" * 72)
    print(f"{icon} {r['verdict']}" + (f"   (phishing probability: {p:.1%})" if p is not None else ""))
    print(f"Model prediction: {r.get('raw_model_verdict', '—')} (predict() = {r.get('raw_model_prediction', '—')})")
    print(f"Probability decision: {r.get('model_probability_verdict', '—')} at {DECISION_THRESHOLD:.0%} phishing threshold")
    print(f"Feature decision: {r.get('feature_verdict', '—')} "
          f"(-1 signals={r.get('phishing_like_count', 0)}, 0 signals={r.get('suspicious_feature_count', 0)})")
    print(f"URL: {r['url']}")
    if r["info"]["final_url"] != r["url"]:
        print(f"Final URL after redirects: {r['info']['final_url']}")
    print("=" * 72)
    if r["verdict"] == "INCONCLUSIVE":
        print("Too many signals could not be measured: the page may be offline or blocked, or you may be "
              "offline. No reliable verdict - do NOT treat as safe.")
    if r["set_to_neutral_0"]:
        print(f"Note: {len(r['set_to_neutral_0'])} feature(s) cannot be measured live and were set to 0 "
              f"(neutral): {', '.join(r['set_to_neutral_0'])}. Reliability is reduced.")
    elif r["unavailable_features"]:
        print(f"Note: {len(r['unavailable_features'])} signal(s) could not be measured "
              f"({', '.join(r['unavailable_features'])}); confidence is reduced.")
    if r.get("rule_reasons"):
        print(f"\nRule-based risk score: {r.get('risk_score', 0)}/100 ({r.get('risk_verdict')})")
        for reason in r["rule_reasons"]:
            print(f"  - +{reason['points']}: {reason['reason']}")
    if r["red_flags"]:
        print("\nWarning signs found:")
        for fl in r["red_flags"]:
            print(f"  - {fl['meaning']}  [{'suspicious' if fl['value'] == 0 else 'phishing-like'}]")
    else:
        print("\nNo individual warning signs found.")
    print("\nThis is a statistical estimate, not a guarantee. When in doubt, don't enter credentials.")


def main():
    ap = argparse.ArgumentParser(description="Phishing URL checker (loads a saved .joblib model)")
    ap.add_argument("url", nargs="?", help="URL to check (omit for interactive mode)")
    ap.add_argument("--model", help="path to the .joblib model file")
    ap.add_argument("--file", help="text file with one URL per line")
    ap.add_argument("--out", help="CSV output path (with --file)")
    ap.add_argument("--json", action="store_true", help="print JSON instead of a report")
    args = ap.parse_args()

    bundle = load_model(resolve_model_path(args.model))
    print(f"Loaded model: {bundle['name']}  ({bundle['path']}, {len(bundle['features'])} features)")

    if args.file:
        urls = [u.strip() for u in Path(args.file).read_text().splitlines() if u.strip()]
        rows = []
        for u in urls:
            try:
                r = analyse(u, bundle)
                rows.append({"url": u, "verdict": r["verdict"], "p_phishing": r["phishing_probability"],
                             "missing": len(r["unavailable_features"])})
            except Exception as e:                      # keep going on bad lines
                rows.append({"url": u, "verdict": f"ERROR: {e}", "p_phishing": "", "missing": ""})
            print(f"{rows[-1]['verdict']:<14} {rows[-1]['p_phishing']!s:<8} {u}")
        if args.out:
            with open(args.out, "w", newline="") as fh:
                w = csv.DictWriter(fh, fieldnames=["url", "verdict", "p_phishing", "missing"])
                w.writeheader()
                w.writerows(rows)
            print(f"Saved -> {args.out}")
        return

    if args.url:
        try:
            r = analyse(args.url, bundle)
        except ValueError as e:
            sys.exit(f"Invalid URL: {e}")
        print(json.dumps(r, indent=2, default=str)) if args.json else print_report(r)
        return

    print("Blank line to quit.")
    while True:
        u = input("\nPaste a URL: ").strip()
        if not u:
            break
        try:
            print_report(analyse(u, bundle))
        except ValueError as e:
            print("Invalid URL:", e)


if __name__ == "__main__":
    main()
