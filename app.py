import os
import google.generativeai as genai
from flask import Flask, render_template, request

# Initialize Flask app
app = Flask(__name__)

# Set your API Key for Google Generative AI
os.environ['GOOGLE_API_KEY'] = 'AIzaSyDPoaPx17CL68O0xhNBqaubSvBB6f2GUXw'  # Replace with your actual API key

# Configure the Generative AI API
genai.configure(api_key=os.getenv('GOOGLE_API_KEY'))

# Function to analyze a URL and return justification for phishing suspicion
def analyze_url(url):
    url = url.rstrip('/')
    model = genai.GenerativeModel('gemini-pro')
    chat = model.start_chat(history=[])
    prompt = f"Is this URL a phishing attempt: {url}?"
    response = chat.send_message(prompt, stream=True)
    justification = ""
    for chunk in response:
        if hasattr(chunk, 'text') and chunk.text:
            justification += f"Response: {chunk.text}\n"
        elif hasattr(chunk, 'safety_ratings') and chunk.safety_ratings:
            for rating in chunk.safety_ratings:
                justification += f"Category: {rating.category}, Probability: {rating.probability}\n"
                if rating.category == 'HARM_CATEGORY_DANGEROUS_CONTENT':
                    justification += "Justification: The content is highly dangerous, indicating a high likelihood of phishing.\n"
    if not justification:
        justification = "No sufficient information to determine phishing suspicion."
    return justification

# Function to analyze email headers for PII redaction
def analyze_email_headers(email_headers):
    model = genai.GenerativeModel('gemini-pro')
    chat = model.start_chat(history=[])
    prompt = f"Analyze the following email headers and identify any sensitive PII information like TO address, FROM address, SMTP IP, etc. Why should each be redacted?\n\n{email_headers}"
    response = chat.send_message(prompt, stream=True)
    pii_justification = ""
    for chunk in response:
        if hasattr(chunk, 'text') and chunk.text:
            pii_justification += f"Response: {chunk.text}\n"
    if not pii_justification:
        pii_justification = "No sensitive PII detected."
    return pii_justification

# Define the route for the homepage
@app.route("/", methods=["GET", "POST"])
def index():
    justification = ""
    normalized_url = ""
    if request.method == "POST":
        url = request.form.get("url")
        normalized_url = url.rstrip('/')
        justification = analyze_url(normalized_url)
    return render_template("index.html", justification=justification, normalized_url=normalized_url)

# Define the route for PII redaction feature
@app.route("/pii-redactor", methods=["POST"])
def pii_redactor():
    email_headers = request.form.get("email_headers")
    pii_justification = analyze_email_headers(email_headers)
    return render_template("index.html", pii_justification=pii_justification)

# Run the app
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 10000)), debug=True)
