from flask import Flask, jsonify, send_from_directory, request
import os
import json
import re
from datetime import datetime

from automation import combined

APP_ROOT = os.path.dirname(os.path.abspath(__file__))
SCANS_DIR = os.path.join(APP_ROOT, "scans")
os.makedirs(SCANS_DIR, exist_ok=True)

app = Flask(__name__, static_folder="dashboard", static_url_path="")


def update_stats_files():
    log_path = os.path.join(APP_ROOT, "automation", "logs", "spam_log.txt")
    detector_dir = os.path.join(APP_ROOT, "spam_detector")
    os.makedirs(detector_dir, exist_ok=True)

    # Ensure blacklist and whitelist exist
    for f_name in ["blacklist.txt", "whitelist.txt"]:
        f_path = os.path.join(detector_dir, f_name)
        if not os.path.exists(f_path):
            with open(f_path, "w", encoding="utf-8") as f:
                f.write("(none)")

    # Read keywords
    keywords = []
    kw_path = os.path.join(detector_dir, "spam_keywords.txt")
    if os.path.exists(kw_path):
        with open(kw_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    parts = line.split(",")
                    if parts:
                        keywords.append(parts[0].lower().strip())

    if not os.path.exists(log_path):
        # Create empty stats files
        with open(os.path.join(detector_dir, "history.csv"), "w", encoding="utf-8") as f:
            f.write("date,total,spam\n")
        with open(os.path.join(detector_dir, "sender_stats.csv"), "w", encoding="utf-8") as f:
            f.write("sender,total,spam,reputation\n")
        with open(os.path.join(detector_dir, "keyword_stats.csv"), "w", encoding="utf-8") as f:
            f.write("keyword,hits\n")
        return

    # Parse logs
    # Format: [YYYY-MM-DD HH:MM:SS] SENDER=... | SUBJECT=... | CLASSIFICATION=... | SPAM_SCORE=...
    log_pattern = re.compile(
        r"\[(?P<date>\d{4}-\d{2}-\d{2})[^\]]*\]\s+SENDER=(?P<sender>.*?)\s*\|\s*SUBJECT=(?P<subject>.*?)\s*\|\s*CLASSIFICATION=(?P<classification>.*?)\s*\|\s*SPAM_SCORE=(?P<score>\d+)"
    )

    history_data = {}  # date -> {total, spam}
    sender_data = {}   # sender -> {total, spam}
    keyword_hits = {kw: 0 for kw in keywords}

    with open(log_path, "r", encoding="utf-8") as f:
        for line in f:
            m = log_pattern.search(line)
            if m:
                d = m.group("date")
                sender = m.group("sender").strip()
                subject = m.group("subject").strip()
                classification = m.group("classification").strip().upper()

                is_spam = 1 if classification in ("SPAM", "PHISHING", "MALICIOUS") else 0

                # History
                if d not in history_data:
                    history_data[d] = {"total": 0, "spam": 0}
                history_data[d]["total"] += 1
                history_data[d]["spam"] += is_spam

                # Senders
                if sender not in sender_data:
                    sender_data[sender] = {"total": 0, "spam": 0}
                sender_data[sender]["total"] += 1
                sender_data[sender]["spam"] += is_spam

                # Keywords hits in subject
                subject_lower = subject.lower()
                for kw in keywords:
                    if kw in subject_lower:
                        keyword_hits[kw] += 1

    # Write history.csv
    with open(os.path.join(detector_dir, "history.csv"), "w", encoding="utf-8") as f:
        f.write("date,total,spam\n")
        for d in sorted(history_data.keys()):
            f.write(f"{d},{history_data[d]['total']},{history_data[d]['spam']}\n")

    # Write sender_stats.csv
    with open(os.path.join(detector_dir, "sender_stats.csv"), "w", encoding="utf-8") as f:
        f.write("sender,total,spam,reputation\n")
        for sender, info in sender_data.items():
            rep = int(((info["total"] - info["spam"]) / info["total"]) * 100)
            f.write(f"{sender},{info['total']},{info['spam']},{rep}\n")

    # Write keyword_stats.csv
    with open(os.path.join(detector_dir, "keyword_stats.csv"), "w", encoding="utf-8") as f:
        f.write("keyword,hits\n")
        for kw, hits in keyword_hits.items():
            f.write(f"{kw},{hits}\n")


@app.route("/")
def index():
    update_stats_files()
    return send_from_directory("dashboard", "dashboard.html")


@app.route("/scan", methods=["POST", "GET"])
def scan():
    # Run scan and enable logging of results
    result = combined.run_scan(fetch_emails=True, notify=False, log_results=True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    base_name = f"scan_{timestamp}"
    json_path = os.path.join(SCANS_DIR, base_name + ".json")
    txt_path = os.path.join(SCANS_DIR, base_name + ".txt")

    # Save JSON
    with open(json_path, "w", encoding="utf-8") as jf:
        json.dump(result, jf, ensure_ascii=False, indent=2)

    # Save human readable text
    with open(txt_path, "w", encoding="utf-8") as tf:
        if result.get("error"):
            tf.write("ERROR: " + result.get("error") + "\n")
        elif result.get("info"):
            tf.write(result.get("info") + "\n")
        else:
            for i, r in enumerate(result.get("results", []), start=1):
                tf.write(f"Email #{i}\n")
                tf.write(f"From: {r.get('sender')}\n")
                tf.write(f"Subject: {r.get('subject')}\n")
                tf.write(f"Score: {r.get('score')}\n")
                tf.write(f"Result: {r.get('classification')}\n")
                tf.write("-" * 40 + "\n")

    download_url = f"/scans/{os.path.basename(txt_path)}"

    # Generate stats files based on new logs
    update_stats_files()

    return jsonify({"result": result, "download": download_url})


@app.route("/spam_detector/<path:filename>")
def serve_spam_detector(filename):
    return send_from_directory(os.path.join(APP_ROOT, "spam_detector"), filename)


@app.route("/automation/logs/<path:filename>")
def serve_automation_logs(filename):
    return send_from_directory(os.path.join(APP_ROOT, "automation", "logs"), filename)


@app.route("/latest_scan")
def latest_scan():
    try:
        files = [f for f in os.listdir(SCANS_DIR) if f.endswith(".txt")]
        if not files:
            return jsonify({"download": None})
        files.sort()
        latest = files[-1]
        return jsonify({"download": f"/scans/{latest}"})
    except Exception:
        return jsonify({"download": None})


@app.route("/scans/<path:filename>")
def scans(filename):
    return send_from_directory(SCANS_DIR, filename, as_attachment=True)


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)

