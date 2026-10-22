"""Sentinel AI prototype - Flask API + static web app.

Run:  python app.py   then open http://localhost:5000 (use phone view in browser devtools)
"""
from flask import Flask, jsonify, request, send_from_directory

from analyzer import analyze_sms, analyze_url

app = Flask(__name__, static_folder="static", static_url_path="/static")


@app.get("/")
def index():
    return send_from_directory("static", "index.html")


@app.get("/api/health")
def health():
    return jsonify(status="ok", service="sentinel-ai")


@app.post("/api/scan/url")
def scan_url():
    data = request.get_json(silent=True) or {}
    result = analyze_url(data.get("url", ""))
    return jsonify(result), (400 if "error" in result else 200)


@app.post("/api/scan/sms")
def scan_sms():
    data = request.get_json(silent=True) or {}
    result = analyze_sms(data.get("text", ""))
    return jsonify(result), (400 if "error" in result else 200)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
