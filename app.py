import whois
import requests
import os
from flask import Flask, render_template, jsonify

app = Flask(__name__)

OPENPHISH_URL = "https://openphish.com/feed.txt"

def fetch_phishing_urls():
    try:
        response = requests.get(OPENPHISH_URL)
        if response.status_code == 200:
            phishing_urls = response.text.splitlines()
            return phishing_urls
        else:
            return {"error": f"Failed to fetch URLs from OpenPhish. Status code: {response.status_code}"}
    except Exception as e:
        return {"error": f"Error fetching URLs from OpenPhish: {str(e)}"}

def check_if_aws_hosted(domain):
    try:
        whois_data = whois.whois(domain)
        if whois_data and ('amazon' in str(whois_data).lower() or 'aws' in str(whois_data).lower()):
            return True
        return False
    except Exception as e:
        return {"error": f"Error performing WHOIS lookup for {domain}: {str(e)}"}

@app.route("/", methods=["GET"])
def index():
    return render_template("index.html")

@app.route("/check-aws", methods=["GET"])
def check_aws():
    phishing_urls = fetch_phishing_urls()
    if isinstance(phishing_urls, dict) and "error" in phishing_urls:
        return jsonify({"error": phishing_urls["error"]})

    aws_hosted_urls = []
    for url in phishing_urls:
        domain = url.split("/")[2]
        if check_if_aws_hosted(domain) or 'amazon' in domain.lower():
            aws_hosted_urls.append(url)

    return jsonify({
        "total_urls": len(phishing_urls),
        "aws_count": len(aws_hosted_urls),
        "aws_urls": aws_hosted_urls
    })

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 10000)), debug=True)
