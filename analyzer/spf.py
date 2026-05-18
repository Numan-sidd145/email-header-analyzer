import re

def analyze_spf(headers):
    auth = headers.get("Authentication-Results", "") + " " + headers.get("Received-SPF", "")

    if re.search(r"spf=pass", auth, re.IGNORECASE):
        result = "pass"
    elif re.search(r"spf=fail", auth, re.IGNORECASE):
        result = "fail"
    elif re.search(r"spf=softfail", auth, re.IGNORECASE):
        result = "softfail"
    elif re.search(r"spf=neutral", auth, re.IGNORECASE):
        result = "neutral"
    else:
        result = "none"

    return {"result": result}