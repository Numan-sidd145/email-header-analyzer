import email
import re

def parse_headers(raw_headers):
    msg = email.message_from_string(raw_headers)

    parsed = {
        "From": msg.get("From", ""),
        "To": msg.get("To", ""),
        "Subject": msg.get("Subject", ""),
        "Return-Path": msg.get("Return-Path", ""),
        "Message-ID": msg.get("Message-ID", ""),
        "Authentication-Results": msg.get("Authentication-Results", ""),
        "Received-SPF": msg.get("Received-SPF", ""),
        "DKIM-Signature": msg.get("DKIM-Signature", ""),
        "Received": msg.get_all("Received", []),
    }

    return parsed

def extract_domain(address):
    if not address:
        return ""
    match = re.search(r'@([A-Za-z0-9.-]+)', address)
    return match.group(1).lower() if match else ""