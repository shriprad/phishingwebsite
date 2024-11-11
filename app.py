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
    url = url.rstrip('/')  # Normalize URL
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
                # Add justification based on the safety category
                if rating.category == 'HARM_CATEGORY_DANGEROUS_CONTENT':
                    justification += f"Justification: {rating.category} with probability {rating.probability}\n"
    
    if not justification:
        justification = "No sufficient information to determine phishing suspicion."
    
    return justification

# Function to analyze email headers and return PII redaction reasons
def analyze_email_headers(headers):
    model = genai.GenerativeModel('gemini-pro')
    chat = model.start_chat(history=[])
    prompt = f"Analyze these email headers and detect any personal identifiable information (PII) or sensitive data: {headers}"
    response = chat.send_message(prompt, stream=True)

    email_analysis = ""

    for chunk in response:
        if hasattr(chunk, 'text') and chunk.text:
            email_analysis += f"Analysis: {chunk.text}\n"

    if not email_analysis:
        email_analysis = "No sensitive data detected in the email headers."

    return email_analysis


# Define the route for the homepage
@app.route("/", methods=["GET", "POST"])
def index():
    justification = ""
    normalized_url = ""
    email_analysis = ""
    
    if request.method == "POST":
        if 'url' in request.form:
            url = request.form.get("url")
            normalized_url = url.rstrip('/')
            justification = analyze_url(normalized_url)
        
        elif 'email_headers' in request.form:
            email_headers = request.form.get("email_headers")
            email_analysis = analyze_email_headers(email_headers)
    
    return render_template("index.html", justification=justification, normalized_url=normalized_url, email_analysis=email_analysis)


# Run the app
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 10000)), debug=True)
