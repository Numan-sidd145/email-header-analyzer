def generate_explanation(headers, spf, dkim, dmarc, risk_score, verdict):
    reasons = []
    positives = []

    # --- SPF ---
    if spf["result"] == "pass":
        positives.append("SPF passed: Sending server is authorized.")
    else:
        reasons.append("SPF failed: Sender may not be authorized.")

    # --- DKIM ---
    if dkim["result"] == "pass":
        positives.append("DKIM passed: Email content integrity verified.")
    else:
        reasons.append("DKIM failed or missing: Message may be altered.")

    # --- DMARC ---
    if dmarc["result"] == "pass":
        positives.append("DMARC passed: Domain alignment verified.")
    else:
        reasons.append("DMARC missing or failed: No strong anti-spoofing protection.")

    # --- Spoofing Check ---
    from_addr = headers.get("From", "")
    return_path = headers.get("Return-Path", "")

    if "@" in from_addr and "@" in return_path:
        from_domain = from_addr.split("@")[-1].strip(">")
        return_domain = return_path.split("@")[-1].strip(">")

        if from_domain != return_domain:
            reasons.append("Mismatch between From and Return-Path domains (possible spoofing).")

    # --- Subject Analysis ---
    subject = headers.get("Subject", "").lower()

    suspicious_words = ["urgent", "blocked", "verify", "suspend", "alert", "password"]

    if any(word in subject for word in suspicious_words):
        reasons.append("Subject contains urgency or threat language (common in phishing).")

    # --- Received Chain ---
    received = headers.get("received", [])
    if len(received) > 3:
        reasons.append("Email passed through multiple relay servers (possible obfuscation).")

    # --- Final Explanation ---
    explanation = {
        "verdict": verdict,
        "risk_score": risk_score,
        "why_suspicious": reasons,
        "why_safe": positives
    }

    return explanation