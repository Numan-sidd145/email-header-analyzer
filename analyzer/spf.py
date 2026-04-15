def analyze_spf(headers):
    auth = headers.get("Authentication-Results", "")

    if "spf=pass" in auth:
        result = "pass"
    elif "spf=fail" in auth:
        result = "fail"
    else:
        result = "neutral"

    return {
        "result": result
    }