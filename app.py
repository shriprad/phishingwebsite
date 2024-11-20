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

def analyze_url(url):
    try:
        # Extract URL components for analysis
        url_components = extract_url_components(url)
        
        # Craft a comprehensive analysis prompt
        analysis_prompt = f"""Perform a detailed phishing URL analysis for: {url}

        URL Components:
        - Full URL: {url_components['full_url']}
        - Domain: {url_components['domain']}
        - Subdomain: {url_components['subdomain']}
        - TLD: {url_components['suffix']}
        - Path: {url_components['path']}
        - Query Parameters: {url_components['query']}

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
            'analysis_time': analysis_time
        }

        return analysis_result

    except Exception as e:
        return {
            'url_components': url_components if 'url_components' in locals() else None,
            'error': str(e),
            'analysis': 'Analysis failed due to an error',
            'analysis_time': 0
        }

@app.route("/fetch-urls")
def fetch_urls():
    try:
        # Fetch the URLs from OpenPhish
        response = requests.get("https://openphish.com/feed.txt", timeout=5)
        urls = response.text.strip().split('\n')[:3]  # Get first 3 URLs

        # Save the fetched URLs to a text file
        with open('fetched_urls.txt', 'w') as f:
            for url in urls:
                f.write(url + '\n')

        return jsonify({"urls": urls})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/", methods=["GET", "POST"])
def index():
    analysis_result = None
    if request.method == "POST":
        url = request.form.get("url")
        analysis_result = analyze_url(url)
    return render_template("index.html", analysis_result=analysis_result)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 10000)), debug=True)
