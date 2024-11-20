import os
import time
import urllib.parse
import tldextract
import google.generativeai as genai
import requests
from bs4 import BeautifulSoup
import ssl
import socket
from flask import Flask, render_template, request, jsonify

app = Flask(__name__)

# Configure Gemini AI
os.environ['GOOGLE_API_KEY'] = 'AIzaSyDPoaPx17CL68O0xhNBqaubSvBB6f2GUXw'
genai.configure(api_key=os.getenv('GOOGLE_API_KEY'))

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

def get_page_title(url):
    """Fetch the webpage and extract the title"""
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        soup = BeautifulSoup(response.text, 'html.parser')
        title = soup.title.string.strip() if soup.title else "No title found"
        return title
    except requests.RequestException as e:
        return f"Error fetching title: {str(e)}"

def check_ssl_tls(url):
    """Check if the URL uses SSL/TLS (HTTPS) and analyze the certificate"""
    parsed_url = urllib.parse.urlparse(url)
    
    if parsed_url.scheme != 'https':
        return {"ssl_status": "Not Secure", "message": "The URL does not use HTTPS."}
    
    try:
        host = parsed_url.netloc
        context = ssl.create_default_context()
        with socket.create_connection((host, 443)) as conn:
            with context.wrap_socket(conn, server_hostname=host) as ssl_socket:
                ssl_info = ssl_socket.getpeercert()
                return {"ssl_status": "Secure", "certificate_info": ssl_info}
    except Exception as e:
        return {"ssl_status": "Error", "message": str(e)}

def analyze_url(url):
    try:
        url_components = extract_url_components(url)
        page_title = get_page_title(url)
        ssl_status = check_ssl_tls(url)
        analysis_prompt = f"""Perform a detailed phishing URL analysis for: {url}
        URL Components: Full URL: {url_components['full_url']}, Domain: {url_components['domain']}
        Please analyze the structure and risks.
        """
        model = genai.GenerativeModel('gemini-pro')
        start_time = time.time()
        response = model.generate_content(analysis_prompt)
        analysis_time = round(time.time() - start_time, 2)

        return {
            'url_components': url_components,
            'analysis': response.text,
            'analysis_time': analysis_time,
            'page_title': page_title,
            'ssl_status': ssl_status
        }
    except Exception as e:
        return {
            'error': str(e),
            'analysis': 'Analysis failed due to an error',
            'analysis_time': 0,
            'page_title': None,
            'ssl_status': None
        }

@app.route("/", methods=["GET", "POST"])
def index():
    analysis_result = None
    if request.method == "POST":
        url = request.form.get("url")
        analysis_result = analyze_url(url)
    return render_template("index.html", analysis_result=analysis_result)

@app.route("/fetch_urls", methods=["GET"])
def fetch_urls():
    """Fetch phishing URLs from OpenPhish"""
    try:
        response = requests.get("https://openphish.com/feed.txt", timeout=10)
        response.raise_for_status()
        urls = response.text.strip().split('\n')
        return jsonify({"count": len(urls), "urls": urls})
    except requests.RequestException as e:
        return jsonify({"error": str(e), "count": 0, "urls": []})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 10000)), debug=True)
