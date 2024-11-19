import os
import time
import urllib.parse
import tldextract
import google.generativeai as genai
import requests
import re
from flask import Flask, render_template, request, jsonify

app = Flask(__name__)

# Configure Gemini AI
os.environ['GOOGLE_API_KEY'] = 'AIzaSyDPoaPx17CL68O0xhNBqaubSvBB6f2GUXw'
genai.configure(api_key=os.getenv('GOOGLE_API_KEY'))

def is_aws_url(url):
    """
    Enhanced check for AWS-related URLs using multiple detection methods
    """
    url_lower = url.lower()
    
    # Common AWS related keywords and patterns
    aws_patterns = [
        # Direct AWS domains
        r'\.amazonaws\.com',
        r'\.aws\.amazon\.com',
        r'aws\.amazon\.com',
        r'amazon\.aws',
        r'\.awsapps\.com',
        r'\.cloudfront\.net',
        r'\.elasticbeanstalk\.com',
        
        # AWS service keywords
        r's3[\.-]',
        r'ec2[\.-]',
        r'rds[\.-]',
        r'iam[\.-]',
        r'lambda[\.-]',
        r'dynamodb[\.-]',
        
        # Common AWS related terms
        r'aws[^a-z]',  # aws followed by non-letter
        r'[^a-z]aws',  # aws preceded by non-letter
        r'amazon[^a-z]web[^a-z]services',
        r'aws[^a-z]console',
        r'aws[^a-z]login',
        r'aws[^a-z]signin',
        r'aws[^a-z]management',
        r'aws[^a-z]portal',
        
        # AWS regions
        r'us-east-[12]',
        r'us-west-[12]',
        r'eu-west-[123]',
        r'eu-central-[1]',
        r'ap-southeast-[12]',
        r'ap-northeast-[12]',
        r'sa-east-1',
        
        # Common phishing patterns
        r'aws.*login',
        r'aws.*signin',
        r'aws.*console',
        r'aws.*account',
        r'aws.*verify',
        r'aws.*secure',
        r'amazon.*aws',
        r'signin.*aws',
        r'console.*aws',
        r'login.*aws',
        
        # URL encoded variations
        r'%2Eaws%2E',
        r'%2Eamazonaws%2E',
    ]
    
    # Additional checks for subdomains and paths
    extracted = tldextract.extract(url_lower)
    domain_parts = [extracted.subdomain, extracted.domain, extracted.suffix]
    path = urllib.parse.urlparse(url_lower).path
    
    # Check all parts of the URL against patterns
    full_url_for_check = f"{'.'.join(domain_parts)}{path}"
    
    # Return True if any pattern matches
    return any(re.search(pattern, full_url_for_check) for pattern in aws_patterns)

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
    # Rest of analyze_url function remains unchanged
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
        response = requests.get("https://openphish.com/feed.txt", timeout=10)
        all_urls = response.text.strip().split('\n')
        
        # Filter AWS-related URLs with improved detection
        aws_urls = []
        for url in all_urls:
            if is_aws_url(url):
                # Add debug information
                components = extract_url_components(url)
                aws_urls.append({
                    'url': url,
                    'domain': components['domain'],
                    'subdomain': components['subdomain'],
                    'path': components['path']
                })
        
        return jsonify({
            "urls": aws_urls,
            "total_urls": len(all_urls),
            "aws_urls_count": len(aws_urls)
        })
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
