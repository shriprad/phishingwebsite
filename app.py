import os
import traceback
import time
import urllib.parse
import tldextract
import google.generativeai as genai
import requests
from bs4 import BeautifulSoup
import ssl
import socket
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from flask import Flask, render_template, request, jsonify

app = Flask(__name__)

# Configure Gemini AI
os.environ['GOOGLE_API_KEY'] = 'AIzaSyDPoaPx17CL68O0xhNBqaubSvBB6f2GUXw'
genai.configure(api_key=os.getenv('GOOGLE_API_KEY'))

# Gmail configuration
SENDER_EMAIL = 'your_gmail@gmail.com'  # Replace with your Gmail address
APP_PASSWORD = 'your_app_password'  # Replace with your Gmail App Password
RECEIVER_EMAIL = 'receiver_email@gmail.com'  # Replace with recipient email

def extract_url_components(url):
    """Extract and analyze various components of the URL"""
    try:
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
    except Exception as e:
        return {
            'error': f"URL parsing error: {str(e)}",
            'full_url': url
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
                return {"ssl_status": "Secure", "certificate_info": str(ssl_info)}
    except Exception as e:
        return {"ssl_status": "Error", "message": str(e)}

def send_email_notification(analysis_result):
    """Send email notification with URL analysis details"""
    try:
        msg = MIMEMultipart()
        msg['From'] = SENDER_EMAIL
        msg['To'] = RECEIVER_EMAIL
        msg['Subject'] = f"Phishing URL Analysis: {analysis_result.get('url_components', {}).get('full_url', 'Unknown URL')}"

        body = f"""Phishing URL Analysis Report

URL Details:
- Full URL: {analysis_result.get('url_components', {}).get('full_url', 'N/A')}
- Domain: {analysis_result.get('url_components', {}).get('domain', 'N/A')}
- Subdomain: {analysis_result.get('url_components', {}).get('subdomain', 'N/A')}
- Page Title: {analysis_result.get('page_title', 'N/A')}
- SSL Status: {analysis_result.get('ssl_status', {}).get('ssl_status', 'Unknown')}

Analysis Time: {analysis_result.get('analysis_time', 0)} seconds

Detailed Analysis:
{analysis_result.get('analysis', 'No analysis available')}

Note: This is an automated email from the Phishing URL Analyzer.
"""
        msg.attach(MIMEText(body, 'plain'))

        with smtplib.SMTP('smtp.gmail.com', 587) as server:
            server.starttls()
            server.login(SENDER_EMAIL, APP_PASSWORD)
            server.send_message(msg)
        
        return True
    except Exception as e:
        print(f"Email sending failed: {e}")
        return False

def analyze_url(url):
    """Comprehensive URL analysis function"""
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
        - Full URL: {url_components.get('full_url', 'N/A')}
        - Domain: {url_components.get('domain', 'N/A')}
        - Subdomain: {url_components.get('subdomain', 'N/A')}
        - TLD: {url_components.get('suffix', 'N/A')}
        - Path: {url_components.get('path', 'N/A')}
        - Query Parameters: {url_components.get('query', 'N/A')}

        Page Title: {page_title}

        SSL/TLS Status: {ssl_status.get('ssl_status', 'Unknown')}
        Certificate Info: {ssl_status.get('certificate_info', 'No certificate info available')}

        Provide a comprehensive security analysis.
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
        print(f"Analysis error: {e}")
        print(traceback.format_exc())
        return {
            'error': f"Analysis failed: {str(e)}",
            'url_components': {'full_url': url}
        }

def fetch_openphish_urls():
    """Fetch URLs from OpenPhish feed with error handling"""
    try:
        response = requests.get('https://openphish.com/feed.txt', timeout=10)
        response.raise_for_status()
        # Limit to first 20 URLs to prevent overwhelming response
        return response.text.splitlines()[:20]
    except requests.RequestException as e:
        print(f"Error fetching URLs: {e}")
        return [f"Error fetching URLs: {str(e)}"]

@app.route("/", methods=["GET", "POST"])
def index():
    analysis_result = None
    fetched_urls = []
    email_sent = False
    error_message = None

    try:
        if request.method == "POST":
            url = request.form.get("url")
            fetch_urls = request.form.get("fetch_urls")

            if url:
                analysis_result = analyze_url(url)
                
                # Send email notification if analysis successful
                if analysis_result and 'error' not in analysis_result:
                    email_sent = send_email_notification(analysis_result)
            
            if fetch_urls:
                fetched_urls = fetch_openphish_urls()
    except Exception as e:
        error_message = f"An error occurred: {str(e)}"
        print(traceback.format_exc())

    return render_template(
        "index.html", 
        analysis_result=analysis_result, 
        fetched_urls=fetched_urls,
        email_sent=email_sent,
        error_message=error_message
    )

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 10000)), debug=True)
