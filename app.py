import os
import google.generativeai as genai
from flask import Flask, render_template, request
import urllib.parse

app = Flask(__name__)

os.environ['GOOGLE_API_KEY'] = 'AIzaSyDPoaPx17CL68O0xhNBqaubSvBB6f2GUXw'
genai.configure(api_key=os.getenv('GOOGLE_API_KEY'))

def analyze_url(url):
    try:
        # Create a detailed prompt for Gemini AI to analyze all features
        analysis_prompt = f"""Analyze this URL for phishing: {url}
        
        Please check and explain the following features in detail:
        1. Is there an IP address in the URL? This is suspicious as legitimate sites rarely use IP addresses.
        2. Is there an @ symbol in the URL? This can be used to trick browsers.
        3. How many dots are in the hostname? More than 3 dots is suspicious.
        4. Are there hyphens (-) in the domain? These are rarely used in legitimate URLs.
        5. Is there URL redirection using '//' in the path?
        6. Is there an HTTPS token in the domain part (not at the start)?
        7. Does it use email submission methods (mail() or mailto:)?
        8. Is it using URL shortening services?
        9. Is the hostname length greater than 25 characters?
        10. Are there sensitive words like 'secure', 'account', 'banking', 'paypal', etc.?
        11. Are there more than 5 slashes in the URL?
        12. Are there Unicode characters in the URL?
        13. For SSL certificates (if https), how old is it?
        14. Analyze anchor tags - are they pointing to different domains?
        15. Check for invisible iframes
        16. What is the website's Alexa rank?

        For each feature, provide:
        1. Whether it's suspicious (YES/NO)
        2. Brief explanation why
        3. Risk score (0-10)

        Finally, provide:
        1. Overall phishing probability score (0-100%)
        2. Risk level (Low/Medium/High)
        3. Detailed justification for the assessment
        """

        # Get Gemini AI analysis
        model = genai.GenerativeModel('gemini-pro')
        chat = model.start_chat(history=[])
        response = chat.send_message(analysis_prompt)

        # Parse URL components for display
        parsed_url = urllib.parse.urlparse(url)
        url_parts = {
            'scheme': parsed_url.scheme,
            'netloc': parsed_url.netloc,
            'path': parsed_url.path,
            'params': parsed_url.params,
            'query': parsed_url.query,
            'fragment': parsed_url.fragment
        }

        return {
            'url': url,
            'url_parts': url_parts,
            'analysis': response.text
        }

    except Exception as e:
        return {
            'url': url,
            'error': str(e),
            'analysis': 'Analysis failed due to an error'
        }

@app.route("/", methods=["GET", "POST"])
def index():
    analysis_result = None
    if request.method == "POST":
        url = request.form.get("url")
        analysis_result = analyze_url(url)
    return render_template("index.html", analysis_result=analysis_result)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 10000)), debug=True)
