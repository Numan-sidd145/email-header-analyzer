import email

def parse_headers(raw_headers):
    msg = email.message_from_string(raw_headers)

    parsed = {
        "From": msg.get("From"),
        "To": msg.get("To"),
        "Subject": msg.get("Subject"),
        "Return-Path": msg.get("Return-Path"),
        "Authentication-Results": msg.get("Authentication-Results"),
        "Received": msg.get_all("Received", []),
        "Message-ID": msg.get("Message-ID")
    }

    return parsed