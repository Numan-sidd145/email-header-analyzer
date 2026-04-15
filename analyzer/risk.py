def calculate_risk(spf, dkim, dmarc, headers):
    score = 0

    if spf["result"] != "pass":
        score += 30

    if dkim["result"] != "pass":
        score += 30

    if dmarc["result"] != "pass":
        score += 40

    if score <= 30:
        verdict = "Safe"
    elif score <= 70:
        verdict = "Suspicious"
    else:
        verdict = "Malicious"

    return score, verdict