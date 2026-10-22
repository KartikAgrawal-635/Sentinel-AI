"""Sentinel AI - explainable risk engine (prototype).

Pure-Python heuristics so the demo works offline. Every signal that raises the
risk score is returned with a plain-English reason (the "Explainable AI" part).
"""
import ipaddress
import re
from pathlib import Path
from urllib.parse import urlparse

BRANDS = ["paypal", "google", "amazon", "apple", "microsoft", "facebook", "instagram",
          "netflix", "paytm", "phonepe", "gpay", "sbi", "hdfc", "icici", "axis",
          "flipkart", "whatsapp", "irctc", "npci", "aadhaar"]
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "cutt.ly", "rb.gy",
              "shorturl.at", "ow.ly", "tiny.cc"}
RISKY_TLDS = {"tk", "xyz", "top", "click", "zip", "mov", "work", "country", "gq", "ml",
              "cf", "ga", "loan", "support", "rest", "icu", "monster"}
URL_KEYWORDS = ["login", "verify", "secure", "update", "account", "bank", "kyc", "otp",
                "free", "prize", "reward", "claim", "winner", "refund", "recharge", "wallet"]
SECOND_LEVEL = {"co", "com", "org", "net", "gov", "ac", "edu"}
LEET = str.maketrans({"0": "o", "1": "l", "3": "e", "5": "s", "$": "s", "@": "a"})

SMS_PATTERNS = [
    (r"\b(urgent|immediately|within \d+ ?(hours?|hrs?|mins?)|expires?|last chance|act now)\b",
     "Creates urgency to rush you into acting", 15),
    (r"\b(blocked|suspended|deactivated|locked|unauthori[sz]ed)\b",
     "Threatens to block or suspend your account", 20),
    (r"\b(otp|pin|password|cvv|card number|upi pin)\b",
     "Asks for or mentions secret credentials (OTP/PIN/password)", 25),
    (r"\b(kyc|aadhaar|pan card|verify your (account|identity|details))\b",
     "Uses a KYC / identity-verification pretext common in scams", 20),
    (r"\b(won|winner|lottery|prize|reward|cashback|gift|free recharge|refund)\b",
     "Promises a prize, reward or refund", 20),
    (r"\b(call|whatsapp|contact) (us )?(now|immediately|on)\b",
     "Pushes you to call or message an unknown number", 10),
]

_blocklist = None


def _load_blocklist():
    global _blocklist
    if _blocklist is None:
        path = Path(__file__).parent / "data" / "blocklist.txt"
        _blocklist = set()
        if path.exists():
            for line in path.read_text().splitlines():
                line = line.strip().lower()
                if line and not line.startswith("#"):
                    _blocklist.add(line)
    return _blocklist


def _levenshtein(a, b):
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def _registered_domain(host):
    parts = host.split(".")
    if len(parts) >= 3 and len(parts[-1]) == 2 and parts[-2] in SECOND_LEVEL:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:]) if len(parts) >= 2 else host


def _verdict(trust):
    if trust >= 75:
        return "safe"
    if trust >= 45:
        return "suspicious"
    return "dangerous"


def analyze_url(raw):
    raw = (raw or "").strip()
    if not raw:
        return {"error": "Please enter a link."}
    candidate = raw if re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", raw) else "http://" + raw
    try:
        parsed = urlparse(candidate)
        host = (parsed.hostname or "").lower()
    except ValueError:
        return {"error": "That doesn't look like a valid link."}
    if not host or "." not in host and not _is_ip(host):
        return {"error": "That doesn't look like a valid link."}

    findings = []

    def add(signal, detail, weight):
        findings.append({"signal": signal, "detail": detail, "weight": weight})

    reg = _registered_domain(host)
    name_label = reg.split(".")[0]
    tld = host.split(".")[-1]
    has_scheme = candidate != "http://" + raw

    if reg in _load_blocklist():
        add("Known threat", f"{reg} is on the Sentinel threat blocklist.", 60)

    if parsed.scheme != "https":
        add("No HTTPS", "The connection is not encrypted, so data you enter can be intercepted.",
            15 if has_scheme else 8)

    if _is_ip(host):
        add("IP address link", "Legitimate services rarely use a raw IP address instead of a domain.", 30)

    if "@" in parsed.netloc:
        add("Hidden destination", "The '@' trick can hide the real website behind a fake-looking name.", 30)

    if "xn--" in host:
        add("Look-alike characters", "The domain uses encoded (punycode) characters that can mimic real brands.", 30)

    if host in SHORTENERS:
        add("Shortened link", "The real destination is hidden behind a URL shortener.", 20)

    if tld in RISKY_TLDS:
        add("Risky domain ending", f".{tld} domains are heavily abused for scams and phishing.", 20)

    if host.count(".") >= 4:
        add("Too many subdomains", "Long subdomain chains are used to bury the real domain name.", 15)

    if name_label.count("-") >= 2:
        add("Many hyphens", "Domains stuffed with hyphens are a common phishing pattern.", 10)

    hits = [k for k in URL_KEYWORDS if k in (host + parsed.path).lower()]
    if hits:
        add("Bait keywords", "The link contains words scammers rely on: " + ", ".join(hits[:4]) + ".",
            min(8 * len(hits), 24))

    # Brand impersonation / typosquatting
    tokens = [t for t in re.split(r"[.\-_]", host) if t]
    flagged = False
    for brand in BRANDS:
        if name_label == brand:
            continue  # looks like the official domain name
        for t in tokens:
            norm = t.translate(LEET)
            if t != brand and norm == brand and not flagged:
                add("Fake brand spelling", f"'{t}' imitates {brand} using swapped characters.", 40)
                flagged = True
            elif len(t) >= 5 and t != brand and _levenshtein(norm, brand) == 1 and not flagged:
                add("Typosquatting", f"'{t}' is one character away from {brand}.", 35)
                flagged = True
        if not flagged and brand in host and name_label != brand:
            add("Brand impersonation",
                f"Mentions '{brand}' but the real domain is {reg}, not the official {brand} site.", 35)
            flagged = True
        if flagged:
            break

    if len(raw) > 100:
        add("Very long link", "Unusually long links are often used to hide malicious parameters.", 8)

    risk = min(sum(f["weight"] for f in findings), 100)
    trust = 100 - risk
    checks_passed = []
    if parsed.scheme == "https":
        checks_passed.append("Uses HTTPS encryption")
    if not findings:
        checks_passed.append("No suspicious patterns detected")
    return {
        "type": "url",
        "input": raw,
        "domain": reg,
        "trust_score": trust,
        "verdict": _verdict(trust),
        "findings": sorted(findings, key=lambda f: -f["weight"]),
        "passed": checks_passed,
    }


def _is_ip(host):
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def analyze_sms(text):
    text = (text or "").strip()
    if not text:
        return {"error": "Please paste a message."}
    findings = []
    lowered = text.lower()
    for pattern, reason, weight in SMS_PATTERNS:
        if re.search(pattern, lowered):
            findings.append({"signal": "Scam wording", "detail": reason, "weight": weight})

    urls = re.findall(r"(?:https?://|www\.)[^\s]+|\b[a-z0-9-]+(?:\.[a-z0-9-]+)*\.[a-z]{2,}/[^\s]*", text, re.I)
    links = []
    worst_link_risk = 0
    for u in urls:
        res = analyze_url(u.rstrip(".,);"))
        if "error" in res:
            continue
        links.append({"url": res["input"], "trust_score": res["trust_score"], "verdict": res["verdict"]})
        worst_link_risk = max(worst_link_risk, 100 - res["trust_score"])
        for f in res["findings"][:2]:
            findings.append({"signal": "Link: " + f["signal"], "detail": f["detail"], "weight": f["weight"]})

    text_risk = sum(f["weight"] for f in findings if f["signal"] == "Scam wording")
    risk = min(100, max(worst_link_risk, 0) + min(text_risk, 60))
    trust = 100 - risk
    return {
        "type": "sms",
        "input": text,
        "trust_score": trust,
        "verdict": _verdict(trust),
        "findings": sorted(findings, key=lambda f: -f["weight"]),
        "links": links,
        "passed": [] if findings else ["No scam patterns or risky links found"],
    }
