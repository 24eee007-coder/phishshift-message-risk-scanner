from flask import Flask, render_template, request
import csv
import joblib
import re
from urllib.parse import urlparse
from sklearn.feature_extraction.text import ENGLISH_STOP_WORDS

app = Flask(__name__)

model = joblib.load("models/phishshift_model.pkl")
vectorizer = joblib.load("models/tfidf_vectorizer.pkl")

# Uncertain zone (FR-04): model probability between these values
ABSTAIN_LOW = 0.35
ABSTAIN_HIGH = 0.65

# Strong phishing cues add more risk, weak cues (also common in
# legitimate mail) add less, so "password" alone does not cause a false alarm.
STRONG_PHRASES = [
    "verify your account", "click here", "otp", "account blocked",
    "account suspended", "claim your prize", "bank details",
    "confirm your identity", "send money", "won a prize", "update payment",
]
WEAK_PHRASES = ["urgent", "password", "limited time"]

# Cues that usually appear in genuine messages (AT-01)
SAFE_CUES = [
    "if you did not request", "if this was you", "if you did not do this",
    "ignore this message", "we never ask for", "never share your",
    "contact the it helpdesk", "official website", "official portal",
    "official mobile app", "no action is needed", "visit your branch",
]

# Demo messages for the test table (AT-01 to AT-03, CP-5)
TEST_CASES = [
    ("AT-01", "legitimate", "Legitimate password-reset notice",
     "You requested a password reset for your campus portal. If this was you, use the link: hxxps://portal[.]example[.]test/home If not, ignore this message."),
    ("AT-01", "legitimate", "Legitimate urgent payroll message",
     "Urgent: payroll calendar updated. Salaries will be credited on the last working day. Contact HR for queries. No action is needed."),
    ("AT-01", "legitimate", "Legitimate urgent meeting",
     "Urgent: the project review is moved to Friday at 10 AM in Seminar Hall."),
    ("AT-02", "phishing", "Phishing with unfamiliar wording",
     "Kindly reconfirm your credentials through the secure form to avoid interruption of your mailbox service."),
    ("AT-02", "phishing", "Phishing, different style",
     "Dear colleague, your storage quota has exceeded. Re-authenticate today to continue receiving mail."),
    ("AT-03", "phishing", "Defanged URL (original)",
     "Your parcel is on hold. Pay customs fee Rs. 49 to release it: hxxp://secure-login[.]example[.]test/verify"),
    ("AT-03", "phishing", "Same message, punctuation changed",
     "YOUR PARCEL IS ON HOLD!!! PAY CUSTOMS FEE RS 49 TO RELEASE IT hxxp://secure-login[.]example[.]test/verify"),
    ("CP-5", "phishing", "Prize message without any link",
     "You won a lottery draw. Send your bank details to receive a laptop."),
]


def explain_message(transformed, top_n=5):
    """Words that pushed the model towards phishing / legitimate."""
    if not hasattr(model, "coef_"):
        return [], []

    classes = list(model.classes_)
    if "phishing" not in classes:
        return [], []

    coef = model.coef_[0]
    if classes[1] != "phishing":
        coef = -coef

    names = vectorizer.get_feature_names_out()
    row = transformed.tocoo()
    contributions = [
        (names[col], value * coef[col])
        for col, value in zip(row.col, row.data)
        if not all(t in ENGLISH_STOP_WORDS for t in names[col].split())
    ]

    phishing_cues = sorted(
        [c for c in contributions if c[1] > 0],
        key=lambda c: c[1], reverse=True
    )[:top_n]
    safe_cues = sorted(
        [c for c in contributions if c[1] < 0],
        key=lambda c: c[1]
    )[:3]

    return [w for w, _ in phishing_cues], [w for w, _ in safe_cues]


def analyze_message(message):
    text = message.lower()

    # 1. Machine learning prediction
    transformed = vectorizer.transform([message])
    probabilities = model.predict_proba(transformed)[0]
    classes = list(model.classes_)

    phishing_probability = 0.0
    if "phishing" in classes:
        phishing_probability = probabilities[classes.index("phishing")]

    # 2. Phrase detection
    found_strong = [p for p in STRONG_PHRASES if p in text]
    found_weak = [p for p in WEAK_PHRASES if p in text]
    found_phrases = found_strong + found_weak
    found_safe = [p for p in SAFE_CUES if p in text]

    # 3. URL analysis (URLs are only read as text, never opened)
    urls = re.findall(
        r"(?:https?|hxxps?)://[^\s<>'\"]+|www\.[^\s<>'\"]+",
        message,
        flags=re.IGNORECASE
    )

    url_results = []
    for url in urls:
        clean_url = url.rstrip(".,!?;:)")
        normal_url = (clean_url.replace("[.]", ".")
                      .replace("hxxp", "http")
                      .replace("HXXP", "http"))

        parsed = urlparse(
            normal_url if normal_url.lower().startswith("http")
            else "http://" + normal_url
        )
        hostname = (parsed.hostname or "").lower()
        reasons = []

        if parsed.scheme != "https":
            reasons.append("Not using HTTPS")
        if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", hostname):
            reasons.append("Uses an IP address instead of a domain name")
        if "@" in normal_url:
            reasons.append("Contains an @ symbol")
        if len(normal_url) > 100:
            reasons.append("Unusually long URL")

        url_results.append({"url": clean_url, "reasons": reasons})

    # 4. Combined risk score
    risk_score = phishing_probability * 100
    risk_score += min(len(found_strong) * 8, 24)
    risk_score += min(len(found_weak) * 3, 6)
    risk_score += sum(12 for item in url_results if item["reasons"])
    risk_score -= min(len(found_safe) * 8, 24)
    risk_score = round(max(0, min(risk_score, 100)), 1)

    if risk_score >= 70:
        risk_level = "High"
    elif risk_score >= 40:
        risk_level = "Medium"
    else:
        risk_level = "Low"

    # 5. Verdict with abstain option (FR-04)
    if risk_level == "High" or phishing_probability >= ABSTAIN_HIGH:
        verdict = "phishing"
        prediction_text = "Phishing Risk Detected"
    elif phishing_probability <= ABSTAIN_LOW:
        verdict = "legitimate"
        prediction_text = "Likely Legitimate"
    else:
        verdict = "uncertain"
        prediction_text = "Uncertain - Verify Manually"

    # 6. Explanation of the model's reasoning
    model_cues, safe_words = explain_message(transformed)

    # 7. Recommendations
    if verdict == "uncertain":
        recommendations = [
            "The tool is not confident. Treat the message with caution.",
            "Verify the sender through an official channel.",
            "Do not click links until you have verified the message.",
        ]
    elif risk_level == "High" or any(i["reasons"] for i in url_results):
        recommendations = [
            "Do not click unexpected links.",
            "Never share your password or OTP.",
            "Verify the sender through an official channel.",
            "Do not enter personal or banking details on unverified websites.",
        ]
    else:
        recommendations = [
            "Check the sender before trusting the message.",
            "Be careful with unexpected links and attachments.",
            "Never share passwords or OTPs.",
        ]

    return {
        "prediction": prediction_text,
        "verdict": verdict,
        "ml_probability": round(phishing_probability * 100, 1),
        "risk_score": risk_score,
        "risk_level": risk_level,
        "found_phrases": found_phrases,
        "safe_cues": found_safe,
        "model_cues": model_cues,
        "safe_words": safe_words,
        "urls": url_results,
        "recommendations": recommendations,
    }


def read_csv_rows(path):
    """Read a results CSV written by train.py (empty list if missing)."""
    try:
        with open(path, newline="", encoding="utf-8") as f:
            return list(csv.DictReader(f))
    except FileNotFoundError:
        return []


def run_test_cases():
    rows = []
    for case_id, expected, title, message in TEST_CASES:
        result = analyze_message(message)
        if result["verdict"] == expected:
            status = "pass"
        elif result["verdict"] == "uncertain":
            status = "uncertain"
        else:
            status = "fail"

        rows.append({
            "case": case_id,
            "expected": expected,
            "title": title,
            "message": message,
            "result": result,
            "status": status,
        })
    return rows


@app.route("/", methods=["GET", "POST"])
def home():
    result = None
    message = ""

    if request.method == "POST":
        message = request.form.get("message", "").strip()
        if message:
            result = analyze_message(message)

    return render_template(
        "index.html",
        result=result,
        message=message,
        test_rows=run_test_cases(),
        comparison=read_csv_rows("results/model_comparison.csv"),
        drift=read_csv_rows("results/robustness_drift.csv"),
    )


@app.route("/tests")
def tests():
    return render_template("tests.html", rows=run_test_cases())


if __name__ == "__main__":
    app.run(debug=True)