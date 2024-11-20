import requests
import socket
import ipaddress
from flask import Flask, render_template, jsonify

app = Flask(__name__)

# OpenPhish URL for phishing URLs
OPENPHISH_URL = "https://openphish.com/feed.txt"
AWS_IP_RANGES_URL = "https://ip-ranges.amazonaws.com/ip-ranges.json"

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

def fetch_aws_ip_ranges():
    """Fetch AWS IP ranges from the official AWS source."""
    try:
        response = requests.get(AWS_IP_RANGES_URL)
        if response.status_code == 200:
            aws_data = response.json()
            return [prefix['ip_prefix'] for prefix in aws_data['prefixes']]
        else:
            return {"error": f"Failed to fetch AWS IP ranges. Status code: {response.status_code}"}
    except Exception as e:
        return {"error": f"Error fetching AWS IP ranges: {str(e)}"}

def resolve_to_ip(url):
    """Resolve the URL to its IP address."""
    try:
        # Extract domain from the URL
        hostname = url.split("/")[2]
        ip = socket.gethostbyname(hostname)
        return ip
    except Exception as e:
        return None

def is_ip_in_aws_ranges(ip, aws_ranges):
    """Check if the IP is within AWS's IP ranges."""
    try:
        ip_obj = ipaddress.ip_address(ip)
        for aws_range in aws_ranges:
            if ip_obj in ipaddress.ip_network(aws_range):
                return True
        return False
    except ValueError as e:
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

    # Step 2: Fetch AWS IP ranges
    aws_ip_ranges = fetch_aws_ip_ranges()
    if isinstance(aws_ip_ranges, dict) and "error" in aws_ip_ranges:
        return jsonify({"error": aws_ip_ranges["error"]})

    # Step 3: Check if the domains are hosted on AWS using DNS lookup and AWS IP ranges
    aws_hosted_urls = []
    for url in phishing_urls:
        domain = url.split("/")[2]  # Extract domain from URL
        ip = resolve_to_ip(url)
        if ip and is_ip_in_aws_ranges(ip, aws_ip_ranges):
            aws_hosted_urls.append(url)

    return jsonify({
        "total_urls": len(phishing_urls),
        "aws_count": len(aws_hosted_urls),
        "aws_urls": aws_hosted_urls
    })

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
