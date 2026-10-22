# Sentinel-AI
Sentinel AI — Prototype
An explainable mobile-security assistant that checks links, messages and QR codes before you interact with them, and tells you why something is risky.
Team Sentinel Squad
What the prototype does
Link scanner — trust score (0–100) with plain-English reasons.
Message scanner — detects scam wording (urgency, fake KYC, prize bait, OTP requests) and checks every link inside.
QR scanner — decode a QR image on-device, then scan the link inside.
Live demo — simulated inbox: tap a link and Sentinel intercepts it with a warning sheet (the MVP workflow from our pitch).
Risk signals checked
Threat blocklist · no HTTPS · raw IP links · @ tricks · punycode look-alikes · URL shorteners · risky TLDs · too many subdomains · hyphen stuffing · bait keywords · brand impersonation & typosquatting (e.g. paypa1.com).
Run it
pip install -r requirements.txt
python app.py
Open http://localhost:5000. On desktop, use your browser's phone view (F12 → device toolbar). To try it on a real phone, open http://<your-laptop-ip>:5000 on the same Wi-Fi.
Run tests: python -m pytest
Project structure
app.py            Flask server + REST API
analyzer.py       Explainable risk engine (links + messages)
data/blocklist.txt  Demo threat blocklist
static/index.html Mobile-first web app
tests/            Unit tests
API
POST /api/scan/url — {"url": "..."}
POST /api/scan/sms — {"text": "..."}
Prototype scope & roadmap
This prototype uses offline heuristics and a small demo blocklist so it works anywhere. Planned next (see pitch deck):
Live threat-intelligence APIs (Google Safe Browsing, VirusTotal, OpenPhish, URLhaus, PhishTank)
Flutter mobile app (iOS & Android) with real SMS/call interception
ML-based risk prediction and community scam reporting
Cyber-awareness learning mode