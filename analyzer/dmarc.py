import re

def analyze_dmarc(headers):
    auth = headers.get("Authentication-Results", "")

    if re.search(r"dmarc=pass", auth, re.IGNORECASE):
        result = "pass"
    elif re.search(r"dmarc=fail", auth, re.IGNORECASE):
        result = "fail"
    else:
        result = "none"

    return {"result": result}