import sys, pathlib
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
from analyzer import analyze_url, analyze_sms


def test_safe_site():
    r = analyze_url("https://www.google.com")
    assert r["verdict"] == "safe" and r["trust_score"] >= 90


def test_blocklisted():
    assert analyze_url("http://secure-sbi-kyc.xyz/login")["verdict"] == "dangerous"


def test_leet_brand():
    r = analyze_url("https://paypa1.com/login")
    assert any("brand" in f["signal"].lower() for f in r["findings"])


def test_ip_link():
    assert analyze_url("http://192.168.4.7/verify")["verdict"] != "safe"


def test_impersonation():
    r = analyze_url("https://hdfc-netbanking-update.xyz")
    assert r["verdict"] in ("suspicious", "dangerous")


def test_official_indian_domain_ok():
    assert analyze_url("https://www.irctc.co.in")["verdict"] == "safe"


def test_sms_scam():
    r = analyze_sms("URGENT: Your SBI account will be blocked. Complete KYC now http://sbi-kyc-update.top/verify")
    assert r["verdict"] == "dangerous" and r["links"]


def test_sms_benign():
    assert analyze_sms("Hey, lunch at 1? Check https://www.wikipedia.org")["verdict"] == "safe"


def test_empty():
    assert "error" in analyze_url("")
