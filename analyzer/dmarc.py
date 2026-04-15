def analyze_dmarc(headers):
    auth = headers.get("Authentication-Results", "")

    if "dmarc=pass" in auth:
        result = "pass"
    elif "dmarc=fail" in auth:
        result = "fail"
    else:
        result = "none"

    return {
        "result": result
    }