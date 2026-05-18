def generate_explanation(headers, spf, dkim, dmarc, risk_score, verdict, risk_reasons):
    safe_points = []

    if spf["result"] == "pass":
        safe_points.append("SPF passed, so the sending server is authorized.")
    if dkim["result"] == "pass":
        safe_points.append("DKIM passed, so the message was not altered.")
    if dmarc["result"] == "pass":
        safe_points.append("DMARC passed, so the sender domain is aligned correctly.")

    if not risk_reasons:
        risk_reasons = ["No major suspicious indicators were detected in the header analysis."]

    if verdict == "Safe":
        summary = "This email appears legitimate."
    elif verdict == "Suspicious":
        summary = "This email has warning signs and should be verified before trusting it."
    else:
        summary = "This email appears risky and may be a phishing or spoofing attempt."

    return {
        "verdict": verdict,
        "risk_score": risk_score,
        "summary": summary,
        "why_suspicious": risk_reasons,
        "why_safe": safe_points
    }