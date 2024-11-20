import subprocess
import requests
from flask import Flask, render_template, jsonify

app = Flask(__name__)

# OpenPhish URL for phishing URLs
OPENPHISH_URL = "https://openphish.com/feed.txt"

def fetch_phishing_urls():
    """Fetch phishing URLs from OpenPhish."""
    try:
        response = requests.get(OPENPHISH_URL)
        if response.status_code == 200:
            phishing_urls = response.text.splitlines()
            return phishing_urls
        else:
            return {"error": f"Failed to fetch URLs from OpenPhish. Status code: {response.status_code}"}
    except Exception as e:
        return {"error": f"Error fetching URLs from OpenPhish: {str(e)}"}

def resolve_to_ip_with_dig(url):
    """Resolve the URL to its IP address using the dig command."""
    try:
        # Extract the domain name from the URL
        domain = url.split("/")[2]

        # Use subprocess to call the dig command
        result = subprocess.run(["dig", "+short", domain], capture_output=True, text=True)

        # Check for any errors in the command output
        if result.returncode != 0:
            return None

        # Return the first IP address found (in case there are multiple)
        ip = result.stdout.strip().splitlines()[0]
        return ip
    except Exception as e:
        return None

def check_if_aws_hosted(ip):
    """Check if the IP is hosted on Amazon by running a whois lookup."""
    try:
        # Use subprocess to call whois
        result = subprocess.run(["whois", ip], capture_output=True, text=True)

        # If the whois command was successful, check for "amazon" or "aws" in the output
        if result.returncode == 0 and ("amazon" in result.stdout.lower() or "aws" in result.stdout.lower()):
            return True
        return False
    except Exception as e:
        return False

@app.route("/", methods=["GET"])
def index():
    return render_template("index.html")

@app.route("/check-aws", methods=["GET"])
def check_aws():
    # Step 1: Fetch phishing URLs from OpenPhish
    phishing_urls = fetch_phishing_urls()
    if isinstance(phishing_urls, dict) and "error" in phishing_urls:
        return jsonify({"error": phishing_urls["error"]})

    # Step 2: Check if the domains are hosted on AWS using DNS lookup and WHOIS
    aws_hosted_urls = []
    for url in phishing_urls:
        ip = resolve_to_ip_with_dig(url)
        if ip and check_if_aws_hosted(ip):
            aws_hosted_urls.append(url)

    return jsonify({
        "total_urls": len(phishing_urls),
        "aws_count": len(aws_hosted_urls),
        "aws_urls": aws_hosted_urls
    })

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 10000)), debug=True)
