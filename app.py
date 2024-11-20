import os
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

def send_email_notification(analysis_result):
    """Send email notification with URL analysis details"""
    try:
        # Create message
        msg = MIMEMultipart()
        msg['From'] = SENDER_EMAIL
        msg['To'] = RECEIVER_EMAIL
        msg['Subject'] = f"Phishing URL Analysis: {analysis_result['url_components']['full_url']}"

        # Compose email body
        body = f"""Phishing URL Analysis Report

URL Details:
- Full URL: {analysis_result['url_components']['full_url']}
- Domain: {analysis_result['url_components']['domain']}
- Subdomain: {analysis_result['url_components']['subdomain']}
- Page Title: {analysis_result['page_title']}
- SSL Status: {analysis_result.get('ssl_status', {}).get('ssl_status', 'Unknown')}

Analysis Time: {analysis_result['analysis_time']} seconds

Detailed Analysis:
{analysis_result['analysis']}

Note: This is an automated email from the Phishing URL Analyzer.
"""
        msg.attach(MIMEText(body, 'plain'))

        # Send email
        with smtplib.SMTP('smtp.gmail.com', 587) as server:
            server.starttls()
            server.login(SENDER_EMAIL, APP_PASSWORD)
            server.send_message(msg)
        
        return True
    except Exception as e:
        print(f"Email sending failed: {e}")
        return False

# [Rest of the existing code remains the same - extract_url_components, get_page_title, check_ssl_tls, analyze_url, fetch_openphish_urls functions]

@app.route("/", methods=["GET", "POST"])
def index():
    analysis_result = None
    fetched_urls = []
    email_sent = False

    if request.method == "POST":
        url = request.form.get("url")
        if url:
            analysis_result = analyze_url(url)
            
            # Send email notification
            if analysis_result:
                email_sent = send_email_notification(analysis_result)
        
        # Check if fetch URLs button was clicked
        if request.form.get("fetch_urls"):
            fetched_urls = fetch_openphish_urls()
    
    return render_template("index.html", 
                           analysis_result=analysis_result, 
                           fetched_urls=fetched_urls,
                           email_sent=email_sent)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 10000)), debug=True)
