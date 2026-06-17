import os
import subprocess
import imaplib
import email
from email.header import decode_header
from datetime import datetime

try:
    from dotenv import load_dotenv
    load_dotenv()
except Exception:
    pass

try:
    from plyer import notification as _plyer_notification
except Exception:
    _plyer_notification = None

# ----------------
# Configuration
# ----------------
IMAP_SERVER = os.getenv("IMAP_SERVER", "imap.gmail.com")
IMAP_PORT = int(os.getenv("IMAP_PORT", "993"))
EMAIL_ADDRESS = os.getenv("EMAIL_ADDRESS", "").strip()
APP_PASSWORD = os.getenv("APP_PASSWORD", "").strip()
MAX_EMAILS_TO_FETCH = int(os.getenv("MAX_EMAILS_TO_FETCH", "5"))
ENABLE_NOTIFICATIONS = os.getenv("ENABLE_NOTIFICATIONS", "True").lower() in (
    "1",
    "true",
    "yes",
)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(BASE_DIR)
SPAM_DETECTOR_EXE = os.path.join(PROJECT_ROOT, "spam_detector", "spam_detector.exe")
LOG_FILE_PATH = os.path.join(BASE_DIR, "logs", "spam_log.txt")


# ----------------
# Helper utilities
# ----------------
def decode_mime_header(raw_value):
    if not raw_value:
        return ""

    decoded_parts = decode_header(raw_value)
    output_text = []

    for part, charset in decoded_parts:
        if isinstance(part, bytes):
            used_charset = charset or "utf-8"
            output_text.append(part.decode(used_charset, errors="replace"))
        else:
            output_text.append(part)

    return "".join(output_text)


def extract_email_body(message):
    if message.is_multipart():
        for part in message.walk():
            content_type = part.get_content_type()
            content_disposition = str(part.get("Content-Disposition", ""))
            if content_type == "text/plain" and "attachment" not in content_disposition.lower():
                payload = part.get_payload(decode=True)
                if payload:
                    charset = part.get_content_charset() or "utf-8"
                    return payload.decode(charset, errors="replace").strip()
    else:
        payload = message.get_payload(decode=True)
        if payload:
            charset = message.get_content_charset() or "utf-8"
            return payload.decode(charset, errors="replace").strip()

    return ""


def validate_credentials():
    if not EMAIL_ADDRESS or not APP_PASSWORD:
        raise ValueError(
            "Missing credentials. Set EMAIL_ADDRESS and APP_PASSWORD in your .env file."
        )


# ----------------
# Email fetching
# ----------------
def fetch_unread_emails():
    validate_credentials()
    unread_email_data = []
    mail = None

    try:
        mail = imaplib.IMAP4_SSL(IMAP_SERVER, IMAP_PORT)
        mail.login(EMAIL_ADDRESS, APP_PASSWORD)
        mail.select("INBOX")

        status, search_data = mail.search(None, "UNSEEN")
        if status != "OK":
            print("Could not search unread emails.")
            return unread_email_data

        email_ids = search_data[0].split()
        if not email_ids:
            return unread_email_data

        latest_ids = email_ids[-MAX_EMAILS_TO_FETCH:]

        for email_id in reversed(latest_ids):
            status, message_data = mail.fetch(email_id, "(RFC822)")
            if status != "OK":
                continue

            for response_part in message_data:
                if not isinstance(response_part, tuple):
                    continue

                raw_email = response_part[1]
                msg = email.message_from_bytes(raw_email)

                subject = decode_mime_header(msg.get("Subject", ""))
                sender = decode_mime_header(msg.get("From", ""))

                # Extract plain text body and attachments list
                attachments = []
                body = ""
                if msg.is_multipart():
                    for part in msg.walk():
                        content_type = part.get_content_type()
                        content_disposition = str(part.get("Content-Disposition", ""))

                        if content_type == "text/plain" and "attachment" not in content_disposition.lower() and not body:
                            payload = part.get_payload(decode=True)
                            if payload:
                                charset = part.get_content_charset() or "utf-8"
                                body = payload.decode(charset, errors="replace").strip()

                        # attachment filename
                        filename = part.get_filename()
                        if filename:
                            attachments.append(filename)
                else:
                    payload = msg.get_payload(decode=True)
                    if payload:
                        charset = msg.get_content_charset() or "utf-8"
                        body = payload.decode(charset, errors="replace").strip()

                unread_email_data.append(
                    {
                        "uid": email_id,
                        "sender": sender,
                        "subject": subject,
                        "body": body,
                        "attachments": ",".join(attachments),
                    }
                )

    finally:
        if mail is not None:
            try:
                mail.logout()
            except Exception:
                pass

    return unread_email_data


# ----------------
# Notifier
# ----------------
def send_spam_notification(subject):
    if not ENABLE_NOTIFICATIONS:
        return

    if _plyer_notification is None:
        print(f"[Notification skipped] Spam Email Detected - Subject: {subject}")
        return

    _plyer_notification.notify(
        title="Spam Email Detected",
        message=f"Subject: {subject}",
        app_name="Spam Filter Mini Project",
        timeout=5,
    )


# ----------------
# C spam detector integration and processing
# ----------------
def run_c_spam_detector(structured_text):
    if not os.path.exists(SPAM_DETECTOR_EXE):
        raise FileNotFoundError(
            f"spam_detector.exe not found at: {SPAM_DETECTOR_EXE}. Compile C code first."
        )

    result = subprocess.run(
        [SPAM_DETECTOR_EXE],
        input=structured_text,
        capture_output=True,
        text=True,
        encoding='utf-8',
        cwd=os.path.dirname(SPAM_DETECTOR_EXE),
        check=False,
    )

    if result.returncode != 0:
        raise RuntimeError(f"C detector failed: {result.stderr.strip()}")

    classification = "SAFE"
    spam_score = 0
    reasons = []
    for line in result.stdout.splitlines():
        if line.startswith("CLASSIFICATION="):
            classification = line.split("=", 1)[1].strip()
        elif line.startswith("SPAM_SCORE="):
            score_text = line.split("=", 1)[1].strip()
            spam_score = int(score_text) if score_text.isdigit() else 0
        elif line.startswith("REASON_"):
            parts = line.split("=", 1)
            if len(parts) == 2:
                reasons.append(parts[1].strip())

    return classification, spam_score, reasons


def append_log(sender, subject, classification, spam_score, reasons=None):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    os.makedirs(os.path.dirname(LOG_FILE_PATH), exist_ok=True)
    reason_str = ""
    if reasons:
        reason_str = " | REASONS=" + "; ".join(reasons)

    line = (
        f"[{timestamp}] "
        f"SENDER={sender} | SUBJECT={subject} | "
        f"CLASSIFICATION={classification} | SPAM_SCORE={spam_score}{reason_str}\n"
    )
    with open(LOG_FILE_PATH, "a", encoding="utf-8") as file:
        file.write(line)


def process_emails(emails, notify=True, log_results=True):
    scan_results = []

    for mail in emails:
        # Build structured input for the C detector
        attachments = mail.get("attachments", "")
        structured = (
            f"SENDER={mail['sender']}\n"
            f"SUBJECT={mail['subject']}\n"
            f"ATTACHMENTS={attachments}\n"
            f"BODY={mail['body']}\n"
        )

        classification, spam_score, reasons = run_c_spam_detector(structured)

        if log_results:
            append_log(
                sender=mail["sender"],
                subject=mail["subject"],
                classification=classification,
                spam_score=spam_score,
                reasons=reasons,
            )

        if notify and classification in ("SPAM", "PHISHING", "MALICIOUS"):
            send_spam_notification(mail["subject"]) 

        scan_results.append(
            {
                "sender": mail["sender"],
                "subject": mail["subject"],
                "body": mail["body"],
                "score": spam_score,
                "classification": classification,
                "reasons": reasons,
            }
        )

    return scan_results


def main():
    try:
        emails = fetch_unread_emails()
    except ValueError as err:
        print(f"Configuration Error: {err}")
        return
    except Exception as err:
        print(f"Unexpected error while reading mail: {err}")
        return

    if not emails:
        print("No unread emails found.")
        return

    print(f"Unread emails fetched: {len(emails)}\n")

    scan_results = process_emails(emails)

    for index, result in enumerate(scan_results, start=1):
        print(f"Email #{index}")
        print(f"From   : {result['sender']}")
        print(f"Subject: {result['subject']}")
        print(f"Score  : {result['score']}")
        print(f"Result : {result['classification']}")
        preview = (result["body"][:250] + "...") if len(result["body"]) > 250 else result["body"]
        print(f"Body   : {preview if preview else '[No plain text body found]'}")
        print("-" * 60)


if __name__ == "__main__":
    main()


# Exposed API for programmatic use (used by server)
def run_scan(fetch_emails=True, notify=False, log_results=False):
    """Run a mail scan and return results as a list of dicts.

    Parameters:
    - fetch_emails: if True, fetch unread emails from IMAP; otherwise return empty list
    - notify: whether to send desktop notifications
    - log_results: whether to append to log file

    Returns a dict: {"results": [...], "error": optional}
    """
    try:
        emails = fetch_unread_emails() if fetch_emails else []
    except ValueError as err:
        return {"results": [], "error": f"Configuration Error: {err}"}
    except Exception as err:
        return {"results": [], "error": f"Unexpected error while reading mail: {err}"}

    if not emails:
        return {"results": [], "info": "No unread emails found."}

    scan_results = process_emails(emails, notify=notify, log_results=log_results)
    return {"results": scan_results}
