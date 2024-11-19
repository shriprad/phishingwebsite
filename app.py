import os
import time
import urllib.parse
import tldextract
import google.generativeai as genai
import requests
from flask import Flask, render_template, request, jsonify

app = Flask(__name__)

# Configure Gemini AI
os.environ['GOOGLE_API_KEY'] = 'AIzaSyDPoaPx17CL68O0xhNBqaubSvBB6f2GUXw'
genai.configure(api_key=os.getenv('GOOGLE_API_KEY'))

def is_aws_hosted(url):
    """Check if a URL is hosted on AWS infrastructure"""
    aws_domains = [
        'amazonaws.com',
        'aws.amazon.com',
        'cloudfront.net',
        's3.amazonaws.com',
        'elasticbeanstalk.com'
    ]
    
    extracted = tldextract.extract(url)
    domain = f"{extracted.domain}.{extracted.suffix}"
    
    return any(aws_domain in domain for aws_domain in aws_domains)

def fetch_openphish_urls():
    """Fetch URLs from OpenPhish feed and filter AWS-hosted ones"""
    try:
        # Note: In a real implementation, you would need to use your OpenPhish API key
        # This is a demonstration using a placeholder URL
        response = requests.get('https://openphish.com/feed.txt', timeout=10)
        
        if response.status_code == 200:
            all_urls = response.text.strip().split('\n')
            aws_urls = [url for url in all_urls if is_aws_hosted(url)]
            return {'success': True, 'urls': aws_urls}
        else:
            return {'success': False, 'error': f'Failed to fetch URLs: {response.status_code}'}
    
    except Exception as e:
        return {'success': False, 'error': str(e)}

@app.route("/fetch-urls", methods=["GET"])
def fetch_urls():
    """API endpoint to fetch AWS-hosted phishing URLs"""
    result = fetch_openphish_urls()
    return jsonify(result)

# Your existing functions remain the same
def extract_url_components(url):
    """Extract and analyze various components of the URL"""
    parsed = urllib.parse.urlparse(url)
    extracted = tldextract.extract(url)
    
    return {
        'full_url': url,
        'scheme': parsed.scheme,
        'netloc': parsed.netloc,
        'path': parsed.path,
        'params': parsed.params,
        'query': parsed.query,
        'fragment': parsed.fragment,
        'subdomain': extracted.subdomain,
        'domain': extracted.domain,
        'suffix': extracted.suffix
    }

# Your existing analyze_url function remains the same
def analyze_url(url):
    # ... (previous implementation remains unchanged)
    pass

@app.route("/", methods=["GET", "POST"])
def index():
    analysis_result = None
    if request.method == "POST":
        url = request.form.get("url")
        analysis_result = analyze_url(url)
    return render_template("index.html", analysis_result=analysis_result)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 10000)), debug=True)
