import re

def analyze_dkim(headers):
    auth = headers.get("Authentication-Results", "") + " " + headers.get("DKIM-Signature", "")

    if re.search(r"dkim=pass", auth, re.IGNORECASE):
        result = "pass"
    elif re.search(r"dkim=fail", auth, re.IGNORECASE):
        result = "fail"
    else:
        result = "none"

    return {"result": result}