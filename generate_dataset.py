import csv
import os
import random
import shutil
from datetime import date, timedelta

random.seed(42)

OUT = os.path.join("data", "messages.csv")
os.makedirs("data", exist_ok=True)
if os.path.exists(OUT):
    shutil.copy(OUT, os.path.join("data", "messages_backup_old.csv"))

BANKS = ["Northbank", "Unity Bank", "Metro Savings", "Riverstone Bank", "Axis Plain Bank"]
PRIZES = ["a new smartphone", "Rs. 50,000", "a laptop", "a gift voucher", "a free vacation"]
COURIERS = ["SwiftPost", "QuickParcel", "ExpressLine", "CityCourier"]
AMOUNTS = ["Rs. 25", "Rs. 49", "Rs. 99", "Rs. 150"]
DAYS = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday"]
TIMES = ["9 AM", "10 AM", "11:30 AM", "2 PM", "4 PM"]
ROOMS = ["Room 204", "Seminar Hall", "Lab 3", "Conference Room B"]
HOURS = ["2 hours", "6 hours", "12 hours", "24 hours"]


def url(kind):
    if kind == "http":
        return random.choice(["hxxp://secure-login[.]example[.]test/verify",
                              "hxxp://account-update[.]example[.]test/confirm"]), "defanged_http"
    if kind == "ip":
        return "hxxp://192[.]0[.]2[.]%d/login" % random.randint(1, 99), "ip_host"
    if kind == "short":
        return "hxxps://sho[.]rt/%s" % random.choice(["a1B2c", "x9Yz3", "Qw7Er"]), "shortener"
    if kind == "https":
        return random.choice(["hxxps://portal[.]example[.]test/home",
                              "hxxps://hr[.]example[.]test/policy"]), "defanged_https"
    return "", "none"


CAMPAIGNS = [
    # ---------------- PHISHING ----------------
    ("ph_bank_block", "phishing", "sms", "lookalike", ["http", "short", "none"],
     ["Account alert"],
     ["Your {bank} account will be blocked. Verify your details immediately! {url}",
      "{bank} notice: unusual login detected. Confirm your identity now or the account is suspended. {url}",
      "Urgent! Your {bank} card is locked. Click here to confirm your password: {url}",
      "Final warning: account blocked within {hours}. Update your bank details here {url}"]),
    ("ph_lottery", "phishing", "email", "free_mail", ["short", "http", "none"],
     ["You are a winner!", "Claim your prize"],
     ["Congratulations! You have won {prize}. Pay a small fee of {amt} to claim your reward. {url}",
      "You won a lottery draw. Send your bank details to receive {prize}. Claim it now! {url}",
      "Winner notice: {prize} is waiting. Reply with your address and processing fee {amt}."]),
    ("ph_delivery_fee", "phishing", "sms", "unknown", ["short", "http"],
     ["Parcel on hold"],
     ["{courier}: your parcel is on hold. Pay customs fee {amt} to release it: {url}",
      "Delivery failed. Re-schedule and pay {amt} now or the package returns. {url}",
      "{courier} alert: address incomplete, confirm your card details to ship. {url}"]),
    ("ph_kyc_update", "phishing", "sms", "lookalike", ["http", "short"],
     ["KYC pending"],
     ["Your KYC is expired. Update immediately to avoid account suspended. {url}",
      "Dear customer, complete KYC verification today or services stop. Share OTP to continue. {url}",
      "{bank}: PAN update required, click here to verify your account. {url}"]),
    ("ph_tax_refund", "phishing", "email", "lookalike", ["http", "https"],
     ["Tax refund available", "Refund notification"],
     ["You are eligible for a tax refund of {prize}. Submit your bank details to receive it. {url}",
      "Refund pending: confirm your identity and account number within {hours}. {url}"]),
    ("ph_job_offer", "phishing", "email", "free_mail", ["https", "none"],
     ["Job offer - immediate joining", "Work from home"],
     ["Congratulations, you are selected for work from home. Pay {amt} registration fee to start. {url}",
      "Job offer confirmed. Send your ID copy and bank details to HR to receive joining letter.",
      "Earn Rs. 5,000 daily from home. Limited time, send money for kit and begin now."]),
    ("ph_tech_support", "phishing", "email", "unknown", ["http", "ip"],
     ["Virus detected", "Security warning"],
     ["Warning! Your device is infected. Call support and share your password for removal. {url}",
      "Your cloud storage is full and will be deleted in {hours}. Verify your account here {url}",
      "Security alert: your email will be closed. Click here to keep it active {url}"]),
    ("ph_ceo_payroll_spoof", "phishing", "email", "lookalike", ["none", "http"],
     ["Quick favour", "Payroll update"],
     ["I am in a meeting, need gift cards urgently. Send money now and I will refund later.",
      "HR: update your payroll bank details today to receive salary. Confirm here {url}",
      "Please change my salary account to the new one attached. Do not call, urgent."]),
    ("ph_invoice", "phishing", "email", "unknown", ["http", "short"],
     ["Invoice overdue", "Payment failed"],
     ["Invoice #{n} is overdue. Update payment here to avoid penalty: {url}",
      "Payment failed for your subscription. Update payment method now: {url}",
      "Your order #{n} could not be processed, confirm card details within {hours}. {url}"]),
    ("ph_social_login", "phishing", "sms", "lookalike", ["http", "short", "ip"],
     ["Login attempt"],
     ["Someone tried to log in to your social account. Secure it now: {url}",
      "Your account will be deleted for policy violation. Appeal immediately: {url}",
      "Verify you are not a robot. Enter your password to keep your profile: {url}"]),
    # ---------------- LEGITIMATE ----------------
    ("lg_password_reset", "legitimate", "email", "corporate", ["https", "none"],
     ["Password reset request", "Your password was changed"],
     ["You requested a password reset for your campus portal. If this was you, use the link: {url} If not, ignore this message.",
      "Your password was changed successfully. If you did not do this, contact the IT helpdesk at the front office.",
      "Password expiry reminder: your password expires in 7 days. Change it from the official portal when convenient."]),
    ("lg_payroll_notice", "legitimate", "email", "corporate", ["https", "none"],
     ["Payroll notice", "Payslip available"],
     ["Your payslip for this month is available on the HR portal. No action is needed.",
      "Payroll calendar: salaries will be credited on the last working day. Contact HR for queries.",
      "Reminder: submit your tax declaration by Friday through the HR portal {url}"]),
    ("lg_urgent_meeting", "legitimate", "email", "corporate", ["none"],
     ["Urgent: meeting moved", "Reminder: review"],
     ["Urgent: the project review is moved to {day} at {time} in {room}.",
      "Reminder: your college project review is tomorrow at {time}.",
      "Please join the team meeting on {day} at {time}. Agenda is in the shared folder.",
      "Your meeting is scheduled for {day} at {time}."]),
    ("lg_delivery_update", "legitimate", "sms", "corporate", ["none", "https"],
     ["Delivery update"],
     ["{courier}: your package will arrive on {day}. Track on the official website.",
      "Your package delivery is delayed. Check the official delivery website.",
      "Order #{n} has been shipped and will arrive within 3 days."]),
    ("lg_bank_official", "legitimate", "sms", "corporate", ["none"],
     ["Bank notification"],
     ["{bank}: Rs. 1,200 debited from your account. If not you, visit your branch. We never ask for OTP.",
      "{bank}: your statement is ready. View it in the official mobile app.",
      "{bank} reminder: never share your PIN or OTP with anyone."]),
    ("lg_it_maintenance", "legitimate", "email", "corporate", ["https", "none"],
     ["Scheduled maintenance"],
     ["The campus network will be down for maintenance on {day} from {time}. Please save your work.",
      "IT notice: please update your laptop software this week. Instructions: {url}"]),
    ("lg_hr_policy", "legitimate", "email", "corporate", ["https"],
     ["Policy update", "Holiday notice"],
     ["The updated leave policy is available here: {url} Please read it before next month.",
      "Office will remain closed on {day} for a public holiday."]),
    ("lg_college_notice", "legitimate", "email", "corporate", ["none", "https"],
     ["Exam timetable", "Lab schedule"],
     ["Your electricity bill is due next week. Please check your official account.",
      "Exam timetable has been published. Check the notice board or portal {url}",
      "Lab session on {day} at {time} in {room}. Bring your record book."]),
]

PER_CAMPAIGN = {"phishing": 34, "legitimate": 36}
rows, seen = [], set()
start = date(2026, 1, 1)
mid = 1

for group, label, channel, sdt, ukinds, subjects, templates in CAMPAIGNS:
    target, tries = PER_CAMPAIGN[label], 0
    count = 0
    while count < target and tries < 2000:
        tries += 1
        kind = random.choice(ukinds)
        u, feat = url(kind)
        text = random.choice(templates).format(
            bank=random.choice(BANKS), prize=random.choice(PRIZES),
            courier=random.choice(COURIERS), amt=random.choice(AMOUNTS),
            day=random.choice(DAYS), time=random.choice(TIMES),
            room=random.choice(ROOMS), hours=random.choice(HOURS),
            n=random.randint(1000, 9999), url=u).strip()
        if text in seen:
            continue
        seen.add(text)
        rows.append({
            "message_id": "M%04d" % mid,
            "channel": channel,
            "subject_or_title": random.choice(subjects),
            "body_text": text,
            "sanitized_url_features": feat if u else "none",
            "sender_domain_type": sdt,
            "label": label,
            "campaign_group": group,
            "collected_date": (start + timedelta(days=random.randint(0, 250))).isoformat(),
        })
        mid += 1
        count += 1

# Near-duplicates on purpose, so dedup (FR-01) has something to remove
for r in random.sample(rows, 12):
    d = dict(r)
    d["message_id"] = "M%04d" % mid
    d["body_text"] = r["body_text"].upper() if random.random() < 0.5 else r["body_text"].rstrip(".!") + "!!"
    rows.append(d)
    mid += 1

random.shuffle(rows)
with open(OUT, "w", newline="", encoding="utf-8") as f:
    w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
    w.writeheader()
    w.writerows(rows)

ph = sum(r["label"] == "phishing" for r in rows)
print("Saved %s | total=%d phishing=%d legitimate=%d campaigns=%d"
      % (OUT, len(rows), ph, len(rows) - ph, len({r['campaign_group'] for r in rows})))