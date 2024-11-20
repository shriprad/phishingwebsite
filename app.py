from flask import Flask, render_template, jsonify
import requests
import re

app = Flask(__name__)

# Define OpenPhish URL for phishing URLs
openphish_url = "https://openphish.com/feed.txt"

def fetch_phishing_urls():
    """Fetch phishing URLs from OpenPhish."""
    try:
        response = requests.get(openphish_url)
        if response.status_code == 200:
            phishing_urls = response.text.splitlines()
            return phishing_urls
        else:
            return {"error": f"Failed to fetch URLs. Status code: {response.status_code}"}
    except Exception as e:
        return {"error": f"Error fetching URLs: {str(e)}"}

def is_aws_hosted(url):
    """Check if a URL belongs to AWS."""
    try:
        aws_pattern = r"(\.amazonaws\.com)"
        return re.search(aws_pattern, url) is not None
    except Exception as e:
        return {"error": f"Error checking URL: {url}. Details: {str(e)}"}

@app.route("/", methods=["GET"])
def index():
    return render_template("index.html")

@app.route("/fetch", methods=["GET"])
def fetch():
    phishing_urls = fetch_phishing_urls()
    if isinstance(phishing_urls, dict) and "error" in phishing_urls:
        return jsonify({"error": phishing_urls["error"]})

    total_urls = len(phishing_urls)
    aws_urls = [url for url in phishing_urls if is_aws_hosted(url)]
    aws_count = len(aws_urls)

    return jsonify({
        "total_urls": total_urls,
        "aws_count": aws_count,
        "aws_urls": aws_urls
    })

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 10000)), debug=True)
