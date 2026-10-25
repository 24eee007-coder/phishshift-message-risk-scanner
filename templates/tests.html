import os
import re
import csv
from datetime import datetime

import joblib
import numpy as np
import pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (accuracy_score, classification_report,
                             confusion_matrix, ConfusionMatrixDisplay,
                             f1_score)

os.makedirs("models", exist_ok=True)
os.makedirs("static", exist_ok=True)
os.makedirs("results", exist_ok=True)

# Campaigns kept out of training (FR-03). 2 phishing + 2 legitimate.
HOLDOUT_CAMPAIGNS = [
    "ph_tax_refund", "ph_social_login",          # unseen phishing tactics
    "lg_password_reset", "lg_urgent_meeting",    # legit but "scary-looking"
]
ABSTAIN_LOW, ABSTAIN_HIGH = 0.35, 0.65           # FR-04: uncertain zone

RULE_PHRASES = [
    "urgent", "verify your account", "click here", "password", "otp",
    "account blocked", "account suspended", "limited time",
    "claim your prize", "bank details", "confirm your identity",
    "send money", "won a prize", "update payment",
]

# ---------------------------------------------------------------- Step 1: load
raw = pd.read_csv("data/messages.csv")
print("Raw rows:", len(raw))
data = raw.dropna(subset=["body_text", "label", "campaign_group"]).copy()
data["label"] = data["label"].str.strip().str.lower()
data["body_text"] = data["body_text"].astype(str)


# ------------------------------------------- Step 2: near-duplicate removal (FR-01)
def normalize(text):
    t = text.lower()
    t = re.sub(r"(hxxps?://|https?://|www\.)\S+", " url ", t)
    t = re.sub(r"\d+", "0", t)
    t = re.sub(r"[^a-z0 ]", " ", t)
    return re.sub(r"\s+", " ", t).strip()


data["norm"] = data["body_text"].apply(normalize)
before = len(data)
data = data.drop_duplicates(subset=["norm"]).reset_index(drop=True)
removed = before - len(data)
print("After near-duplicate removal: %d rows (%d removed)" % (len(data), removed))
data[["message_id", "campaign_group", "label", "body_text"]].to_csv(
    "results/deduplicated_messages.csv", index=False)

# --------------------------------- Step 3: campaign-separated split (FR-03)
test_mask = data["campaign_group"].isin(HOLDOUT_CAMPAIGNS)
train_df, test_df = data[~test_mask], data[test_mask]
print("Train: %d rows | Holdout (unseen campaigns): %d rows"
      % (len(train_df), len(test_df)))
overlap = set(train_df["norm"]) & set(test_df["norm"])
print("Template overlap train/test:", len(overlap), "(must be 0)")

X_train, y_train = train_df["body_text"], train_df["label"]
X_test, y_test = test_df["body_text"], test_df["label"]

vectorizer = TfidfVectorizer(lowercase=True, ngram_range=(1, 2), min_df=1)
Xtr = vectorizer.fit_transform(X_train)
Xte = vectorizer.transform(X_test)


# ---------------------------------------------- Step 4: three approaches (FR-02)
def rules_predict(texts):
    out = []
    for t in texts:
        t = t.lower()
        out.append("phishing" if any(p in t for p in RULE_PHRASES) else "legitimate")
    return np.array(out)


lr = LogisticRegression(max_iter=1000, class_weight="balanced")
lr.fit(Xtr, y_train)
rf = RandomForestClassifier(n_estimators=200, random_state=42,
                            class_weight="balanced")
rf.fit(Xtr, y_train)


def fpr(y_true, y_pred):
    legit = (np.array(y_true) == "legitimate")
    if legit.sum() == 0:
        return float("nan")
    return float(((np.array(y_pred) == "phishing") & legit).sum() / legit.sum())


preds = {
    "Rules (keywords)": rules_predict(X_test),
    "TF-IDF + Logistic Regression": lr.predict(Xte),
    "TF-IDF + Random Forest": rf.predict(Xte),
}

rows = []
for name, p in preds.items():
    rows.append({
        "model": name,
        "accuracy": round(accuracy_score(y_test, p), 3),
        "f1_phishing": round(f1_score(y_test, p, pos_label="phishing"), 3),
        "false_positive_rate": round(fpr(y_test, p), 3),
    })
results = pd.DataFrame(rows)
print("\n=== Model comparison on UNSEEN campaigns ===")
print(results.to_string(index=False))
results.to_csv("results/model_comparison.csv", index=False)

print("\nClassification report (Logistic Regression, holdout):")
print(classification_report(y_test, preds["TF-IDF + Logistic Regression"]))

# ---------------------------------- Step 5: abstain option (FR-04)
proba = lr.predict_proba(Xte)
p_phish = proba[:, list(lr.classes_).index("phishing")]
decision = np.where(p_phish >= ABSTAIN_HIGH, "phishing",
                    np.where(p_phish <= ABSTAIN_LOW, "legitimate", "uncertain"))
abstain_rate = float((decision == "uncertain").mean())
decided = decision != "uncertain"
acc_decided = accuracy_score(y_test[decided], decision[decided]) if decided.any() else float("nan")
print("\nAbstain rate: %.1f%% | Accuracy on decided messages: %.3f"
      % (abstain_rate * 100, acc_decided))

# ------------------- Step 6: FPR on legit urgent/password messages (FR-05, AT-01)
test_eval = test_df.copy()
test_eval["lr_pred"] = preds["TF-IDF + Logistic Regression"]
test_eval["rule_pred"] = preds["Rules (keywords)"]
scary = test_eval[(test_eval["label"] == "legitimate") &
                  (test_eval["body_text"].str.lower().str.contains("password|urgent|payroll|otp"))]
print("\nLegit 'scary-looking' messages in holdout:", len(scary))
if len(scary):
    print("  Rules false-positive rate: %.3f" % (scary["rule_pred"] == "phishing").mean())
    print("  LogReg false-positive rate: %.3f" % (scary["lr_pred"] == "phishing").mean())
    wrong = scary[scary["lr_pred"] == "phishing"].head(3)
    for _, r in wrong.iterrows():
        print("  FP example:", r["body_text"][:90])


# ------------------------ Step 7: robustness drift (FR-05, AT-03, CP-5)
def perturb(text, mode):
    if mode == "uppercase":
        return text.upper()
    if mode == "defang_change":
        return text.replace("hxxp", "http").replace("[.]", ".")
    if mode == "punctuation":
        return re.sub(r"[.!?:,]", "", text) + " !!!"
    return text


drift_rows = []
base_acc = accuracy_score(y_test, preds["TF-IDF + Logistic Regression"])
base_prob = p_phish.mean()
for mode in ["uppercase", "defang_change", "punctuation"]:
    Xp = vectorizer.transform(X_test.apply(lambda t: perturb(t, mode)))
    pp = lr.predict(Xp)
    prob = lr.predict_proba(Xp)[:, list(lr.classes_).index("phishing")]
    drift_rows.append({
        "perturbation": mode,
        "accuracy": round(accuracy_score(y_test, pp), 3),
        "accuracy_drift": round(accuracy_score(y_test, pp) - base_acc, 3),
        "mean_phish_prob_shift": round(float(prob.mean() - base_prob), 3),
    })
drift = pd.DataFrame(drift_rows)
print("\n=== Robustness drift (Logistic Regression) ===")
print(drift.to_string(index=False))
drift.to_csv("results/robustness_drift.csv", index=False)

# ---------------------------------------------------------- Step 8: graphs
# Large, readable fonts
plt.rcParams.update({
    "font.size": 14, "axes.titlesize": 17, "axes.titleweight": "bold",
    "axes.labelsize": 15, "xtick.labelsize": 13, "ytick.labelsize": 13,
    "legend.fontsize": 13,
})


def save_fig(path):
    plt.tight_layout()
    plt.savefig(path, dpi=150, bbox_inches="tight")
    plt.close()


# Graph 1: label distribution
counts = data["label"].value_counts()
colors = ["#d9534f" if name == "phishing" else "#2e9d5b" for name in counts.index]
fig, ax = plt.subplots(figsize=(7, 5))
bars = ax.bar(counts.index, counts.values, color=colors)
ax.bar_label(bars, fontsize=15, fontweight="bold", padding=3)
ax.set_title("Graph 1: Label Distribution (after dedup)")
ax.set_xlabel("Label")
ax.set_ylabel("Messages")
ax.set_ylim(0, counts.max() * 1.15)
save_fig("static/distribution.png")

# Graph 2: campaign distribution
camp = data["campaign_group"].value_counts().sort_values()
fig, ax = plt.subplots(figsize=(8, 7))
bars = ax.barh(camp.index, camp.values, color="#1f8fd0")
ax.bar_label(bars, fontsize=12, padding=3)
ax.set_title("Graph 2: Messages per Campaign")
ax.set_xlabel("Messages")
ax.set_ylabel("Campaign")
ax.set_xlim(0, camp.max() * 1.15)
save_fig("static/campaigns.png")

# Graph 3: confusion matrix on the campaign holdout
fig, ax = plt.subplots(figsize=(6.5, 5.5))
ConfusionMatrixDisplay.from_predictions(
    y_test, preds["TF-IDF + Logistic Regression"],
    ax=ax, cmap="Blues", text_kw={"fontsize": 22, "fontweight": "bold"})
ax.set_title("Graph 3: Confusion Matrix\n(unseen campaigns)")
save_fig("static/confusion_matrix.png")

# Graph 4: model comparison
fig, ax = plt.subplots(figsize=(10, 6))
results.set_index("model")[["accuracy", "f1_phishing", "false_positive_rate"]].plot(
    kind="bar", ax=ax, width=0.8)
for container in ax.containers:
    ax.bar_label(container, fmt="%.2f", fontsize=11, padding=2)
ax.set_title("Graph 4: Model Comparison (unseen campaigns)")
ax.set_ylabel("Score")
ax.set_xlabel("")
ax.set_ylim(0, 1.2)
plt.setp(ax.get_xticklabels(), rotation=0, ha="center")
ax.legend(loc="upper center", bbox_to_anchor=(0.5, -0.12), ncol=3)
save_fig("static/model_comparison.png")

# ------------------------------------------------- Step 9: save model + log
joblib.dump(lr, "models/phishshift_model.pkl")
joblib.dump(vectorizer, "models/tfidf_vectorizer.pkl")

log_file = "experiment_log.csv"
new_file = not os.path.exists(log_file)
with open(log_file, "a", newline="", encoding="utf-8") as f:
    w = csv.writer(f)
    if new_file:
        w.writerow(["timestamp", "rows_raw", "rows_dedup", "train", "holdout",
                    "holdout_campaigns", "lr_accuracy", "lr_fpr", "abstain_rate"])
    w.writerow([datetime.now().isoformat(timespec="seconds"), len(raw), len(data),
                len(train_df), len(test_df), "|".join(HOLDOUT_CAMPAIGNS),
                results.loc[1, "accuracy"], results.loc[1, "false_positive_rate"],
                round(abstain_rate, 3)])

print("\nModel, vectorizer, graphs, results and experiment log saved!")