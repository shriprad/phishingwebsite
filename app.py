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
os.environ['GOOGLE_API_KEY'] = 'AIzaSyDIIBtiqZeazI5HMbHvnI7udMTz52D25aQ'
genai.configure(api_key=os.getenv('GOOGLE_API_KEY'))
response = genai.generate_content("Check this URL: example.com", timeout=60)  # Increase timeout

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
        # Get the host from the URL
        host = parsed_url.netloc
        
        # Establish an SSL connection to the host
        context = ssl.create_default_context()
        with socket.create_connection((host, 443)) as conn:
            with context.wrap_socket(conn, server_hostname=host) as ssl_socket:
                ssl_info = ssl_socket.getpeercert()
                # You can add more certificate validation checks here if needed
                return {"ssl_status": "Secure", "certificate_info": ssl_info}
    except Exception as e:
        return {"ssl_status": "Error", "message": str(e)}

def analyze_url(url):
    try:
        # Extract URL components for analysis
        url_components = extract_url_components(url)
        
        # Get the page title (which may give brand information)
        page_title = get_page_title(url)
        
        # Check SSL/TLS status
        ssl_status = check_ssl_tls(url)
        
        # Craft a comprehensive analysis prompt
        analysis_prompt = f"""Perform a detailed phishing URL analysis for: {url}

        URL Components:
        - Full URL: {url_components['full_url']}
        - Domain: {url_components['domain']}
        - Subdomain: {url_components['subdomain']}
        - TLD: {url_components['suffix']}
        - Path: {url_components['path']}
        - Query Parameters: {url_components['query']}

        Page Title: {page_title}

        SSL/TLS Status: {ssl_status['ssl_status']}
        Certificate Info: {ssl_status.get('certificate_info', 'No certificate info available')}

        Please provide a comprehensive security analysis including:

        1. Brand Impersonation Analysis:
        - Identify any legitimate brands being impersonated
        - Explain the impersonation techniques used
        - Compare with legitimate domain patterns for identified brands
        
        2. URL Structure Analysis:
        - Analyze domain and subdomain patterns
        - Identify suspicious URL patterns
        - Check for typosquatting or homograph attacks
        
        3. Technical Risk Indicators:
        - Presence of suspicious URL patterns
        - Domain age and reputation indicators
        - SSL/TLS usage analysis
        - Redirect patterns
        
        4. Social Engineering Indicators:
        - Urgency or pressure tactics in URL
        - Brand-related keywords
        - Security-related keywords
        - Common phishing patterns
        
        5. Provide a detailed phishing risk assessment:
        - Calculate a phishing probability score (0-100%)
        - Assign a risk level (Low/Medium/High)
        - List specific security concerns
        - Provide a detailed justification for the assessment

        6. Security Recommendations:
        - Specific warnings if malicious
        - Safe browsing recommendations
        - Alternative legitimate URLs if brand impersonation detected

        Format the response clearly with section headers and bullet points.
        """

        # Get Gemini AI analysis
        model = genai.GenerativeModel('gemini-pro')
        start_time = time.time()
        response = model.generate_content(analysis_prompt)
        analysis_time = round(time.time() - start_time, 2)

        # Extract key information from the response
        analysis_result = {
            'url_components': url_components,
            'analysis': response.text,
            'analysis_time': analysis_time,
            'page_title': page_title,
            'ssl_status': ssl_status
        }

        return analysis_result

    except Exception as e:
        return {
            'url_components': url_components if 'url_components' in locals() else None,
            'error': str(e),
            'analysis': 'Analysis failed due to an error',
            'analysis_time': 0,
            'page_title': None,
            'ssl_status': None
        }

def fetch_openphish_urls():
    """Fetch URLs from OpenPhish feed"""
    try:
        response = requests.get('https://openphish.com/feed.txt', timeout=10)
        response.raise_for_status()
        return response.text.splitlines()
    except requests.RequestException as e:
        return [f"Error fetching URLs: {str(e)}"]

@app.route("/", methods=["GET", "POST"])
def index():
    analysis_result = None
    fetched_urls = []
    if request.method == "POST":
        url = request.form.get("url")
        if url:
            analysis_result = analyze_url(url)
        
        # Check if fetch URLs button was clicked
        if request.form.get("fetch_urls"):
            fetched_urls = fetch_openphish_urls()
    
    return render_template("index.html", analysis_result=analysis_result, fetched_urls=fetched_urls)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 10000)), debug=True)
