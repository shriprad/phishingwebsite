import os
import time
import urllib.parse
import tldextract
import google.generativeai as genai
from flask import Flask, render_template, request, jsonify
import requests
import re

app = Flask(__name__)

# Configure Gemini AI
os.environ['GOOGLE_API_KEY'] = 'AIzaSyDPoaPx17CL68O0xhNBqaubSvBB6f2GUXw'
genai.configure(api_key=os.getenv('GOOGLE_API_KEY'))

# OpenPhish URL
OPENPHISH_URL = "https://openphish.com/feed.txt"

def fetch_phishing_urls():
    """Fetch phishing URLs from OpenPhish."""
    try:
        # Use the defined OpenPhish URL
        response = requests.get(OPENPHISH_URL)
        if response.status_code == 200:
            phishing_urls = response.text.splitlines()
            return phishing_urls
        else:
            return {"error": f"Failed to fetch URLs. Status code: {response.status_code}"}
    except Exception as e:
        return {"error": f"Error fetching URLs: {str(e)}"}

def filter_aws_urls(phishing_urls):
    """Filter AWS-hosted URLs."""
    aws_pattern = r"(\.amazonaws\.com)"
    try:
        aws_urls = [url for url in phishing_urls if re.search(aws_pattern, url)]
        return aws_urls
    except Exception as e:
        return {"error": f"Error filtering AWS URLs: {str(e)}"}

@app.route("/", methods=["GET", "POST"])
def index():
    analysis_result = None
    if request.method == "POST":
        url = request.form.get("url")
        analysis_result = analyze_url(url)
    return render_template("index.html", analysis_result=analysis_result)

@app.route("/fetch", methods=["GET"])
def fetch():
    phishing_urls = fetch_phishing_urls()
    if isinstance(phishing_urls, dict) and "error" in phishing_urls:
        return jsonify({"error": phishing_urls["error"]})
    aws_urls = filter_aws_urls(phishing_urls)
    if isinstance(aws_urls, dict) and "error" in aws_urls:
        return jsonify({"error": aws_urls["error"]})
    return jsonify({"aws_urls": aws_urls})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 10000)), debug=True)
