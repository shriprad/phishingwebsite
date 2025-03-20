import os
import time
import requests
import urllib.parse
import tldextract
from bs4 import BeautifulSoup
import ssl
import socket
from flask import Flask, render_template, request, jsonify

app = Flask(__name__)

# Configure DeepSeek API
DEEPSEEK_API_KEY = "sk-d017a79fccd048db86b92cec9c176188"
DEEPSEEK_URL = "https://api.deepseek.com/v1/chat/completions"

def analyze_url(url):
    try:
        # Extract URL components
        url_components = extract_url_components(url)
        page_title = get_page_title(url)
        ssl_status = check_ssl_tls(url)

        # Analysis Prompt
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

        Please provide:
        1. Phishing risk score (0-100%)
        2. Security concerns with justification
        3. Recommendations for safe browsing
        """

        # Send request to DeepSeek API
        start_time = time.time()
        headers = {"Authorization": f"Bearer {DEEPSEEK_API_KEY}", "Content-Type": "application/json"}
        payload = {
            "model": "deepseek-chat",
            "messages": [{"role": "user", "content": analysis_prompt}],
            "temperature": 0.7
        }
        response = requests.post(DEEPSEEK_URL, headers=headers, json=payload)
        response.raise_for_status()
        deepseek_response = response.json()
        
        analysis_time = round(time.time() - start_time, 2)
        analysis_text = deepseek_response.get("choices", [{}])[0].get("message", {}).get("content", "No response received.")

        return {
            'url_components': url_components,
            'analysis': analysis_text,
            'analysis_time': analysis_time,
            'page_title': page_title,
            'ssl_status': ssl_status
        }

    except Exception as e:
        return {
            'url_components': url_components if 'url_components' in locals() else None,
            'error': str(e),
            'analysis': 'Analysis failed due to an error',
            'analysis_time': 0,
            'page_title': None,
            'ssl_status': None
        }

