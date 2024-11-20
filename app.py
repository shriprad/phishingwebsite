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
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

app = Flask(__name__)

# Configure Gemini AI
os.environ['GOOGLE_API_KEY'] = 'AIzaSyDPoaPx17CL68O0xhNBqaubSvBB6f2GUXw'
genai.configure(api_key=os.getenv('GOOGLE_API_KEY'))

# Gmail configuration
sender_email = 'freephishingreports@gmail.com'
app_password = 'fpye icmx zsxg otpt'
receiver_email = 'trustandsafety@support.aws.com'

def send_email_report(analysis_result):
    """Send phishing URL analysis report via email"""
    try:
        # Create message
        message = MIMEMultipart()
        message['From'] = sender_email
        message['To'] = receiver_email
        message['Subject'] = f"Phishing URL Analysis: {analysis_result['url_components']['full_url']}"

        # Compose email body
        body = f"""Phishing URL Analysis Report

URL: {analysis_result['url_components']['full_url']}
Domain: {analysis_result['url_components']['domain']}
Subdomain: {analysis_result['url_components']['subdomain']}
Page Title: {analysis_result['page_title']}
SSL Status: {analysis_result.get('ssl_status', {}).get('ssl_status', 'N/A')}

Detailed Analysis:
{analysis_result['analysis']}

Analysis Time: {analysis_result['analysis_time']} seconds
"""
        message.attach(MIMEText(body, 'plain'))

        # Send email
        with smtplib.SMTP_SSL('smtp.gmail.com', 465) as server:
            server.login(sender_email, app_password)
            server.send_message(message)
        
        return True
    except Exception as e:
        print(f"Email sending failed: {e}")
        return False

# [Rest of the previous code remains the same, just add the send_email_report function]

@app.route("/", methods=["GET", "POST"])
def index():
    analysis_result = None
    fetched_urls = []
    email_sent = False
    
    if request.method == "POST":
        url = request.form.get("url")
        if url:
            analysis_result = analyze_url(url)
            
            # Send email report
            if analysis_result:
                email_sent = send_email_report(analysis_result)
        
        # Check if fetch URLs button was clicked
        if request.form.get("fetch_urls"):
            fetched_urls = fetch_openphish_urls()
    
    return render_template("index.html", 
                           analysis_result=analysis_result, 
                           fetched_urls=fetched_urls,
                           email_sent=email_sent)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 10000)), debug=True)
