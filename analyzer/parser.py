import re

def parse_headers(raw):
    headers = {}

    lines = raw.split("\n")

    for line in lines:
        if ":" in line:
            key, value = line.split(":", 1)
            headers[key.strip()] = value.strip()

    headers["received"] = re.findall(r"Received: (.*)", raw)

    return headers