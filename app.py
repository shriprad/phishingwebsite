from flask import Flask, request, jsonify, render_template
import os
import requests

app = Flask(__name__)

# Replace with your actual API key
os.environ['GOOGLE_API_KEY'] = 'AIzaSyDPoaPx17CL68O0xhNBqaubSvBB6f2GUXw'

# Define the 16 features for analysis
FEATURES = [
    "Page Reputation Score", "Phishing Detection", "Malware Detection",
    "SSL/TLS Status", "Domain Age", "Hosting Provider Reputation",
    "Content Authenticity", "Redirection Analysis", "Suspicious Links",
    "Contact Information Verification", "Social Media Presence",
    "Privacy Policy Presence", "Terms of Service Presence",
    "Cookie Policy Detection", "Trustworthiness Score", "User Reviews and Ratings"
]

# Route for the root URL to render the form
@app.route('/')
def index():
    return render_template('index.html')

# Function to analyze the URL
def analyze_url(url):
    api_key = os.getenv('GOOGLE_API_KEY')
    api_url = f"https://gemini.googleapis.com/v1/analyze?url={url}&features={','.join(FEATURES)}&key={api_key}"
    
    response = requests.get(api_url)
    data = response.json()

    # Process the data to ensure each feature is handled
    analysis_results = {feature: data.get(feature, "Not Available") for feature in FEATURES}
    
    return {
        "url": url,
        "analysis_results": analysis_results
    }

# Route to handle URL analysis
@app.route('/analyze', methods=['POST'])
def analyze():
    request_data = request.get_json()
    url = request_data.get('url')
    
    if not url:
        return jsonify({"error": "URL is required"}), 400
    
    analysis = analyze_url(url)
    
    return jsonify(analysis)

# Run the app
if __name__ == '__main__':
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 100000)), debug=True)
