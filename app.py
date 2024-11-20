import os
import requests
import re
from flask import Flask, render_template, request, jsonify

app = Flask(__name__)

# OpenPhish URL
OPENPHISH_URL = "https://openphish.com/feed.txt"

def fetch_phishing_urls():
    """Fetch all phishing URLs from OpenPhish."""
    try:
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
    return render_template("index.html")

@app.route("/fetch", methods=["GET"])
def fetch():
    phishing_urls = fetch_phishing_urls()
    if isinstance(phishing_urls, dict) and "error" in phishing_urls:
        return jsonify({"error": phishing_urls["error"]})

    total_count = len(phishing_urls)
    aws_urls = filter_aws_urls(phishing_urls)
    if isinstance(aws_urls, dict) and "error" in aws_urls:
        return jsonify({"error": aws_urls["error"]})

    aws_count = len(aws_urls)

    return jsonify({
        "total_urls": total_count,
        "aws_count": aws_count,
        "aws_urls": aws_urls
    })

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 10000)), debug=True)
