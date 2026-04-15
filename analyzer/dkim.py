def analyze_dkim(headers):
    auth = headers.get("Authentication-Results", "")

    if "dkim=pass" in auth:
        result = "pass"
    elif "dkim=fail" in auth:
        result = "fail"
    else:
        result = "none"

    return {
        "result": result
    }