import re

def _get_domain(address):
    if not address:
        return ""
    match = re.search(r'@([A-Za-z0-9.-]+)', address)
    return match.group(1).lower() if match else ""

def _is_spoofed(headers):
    from_domain = _get_domain(headers.get("From", ""))
    return_path_domain = _get_domain(headers.get("Return-Path", ""))
    return from_domain and return_path_domain and from_domain != return_path_domain

def calculate_risk(spf, dkim, dmarc, headers):
    score = 0
    reasons = []

    # Authentication checks
    if spf["result"] != "pass":
        score += 20
        reasons.append("SPF did not pass.")

    if dkim["result"] != "pass":
        score += 20
        reasons.append("DKIM did not pass.")

    if dmarc["result"] != "pass":
        score += 25
        reasons.append("DMARC did not pass.")

    # Spoofing check
    if _is_spoofed(headers):
        score += 30
        reasons.append("From and Return-Path domains do not match.")

    # Subject analysis
    subject = headers.get("Subject", "").lower()
    suspicious_words = [
        "urgent", "verify", "password", "blocked", "suspend",
        "account", "payment", "login", "security alert", "action required"
    ]
    if any(word in subject for word in suspicious_words):
        score += 15
        reasons.append("Subject contains suspicious or urgent language.")

    # Received chain check
    received_count = len(headers.get("Received", []))
    if received_count > 3:
        score += 10
        reasons.append("Email passed through multiple relay servers.")

    score = min(score, 100)

    if score <= 30:
        verdict = "Safe"
    elif score <= 70:
        verdict = "Suspicious"
    else:
        verdict = "Malicious"

    return score, verdict, reasons