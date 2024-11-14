from flask import Flask, request, jsonify
import os
import requests

app = Flask(__name__)
os.environ['GOOGLE_API_KEY'] = 'AIzaSyDPoaPx17CL68O0xhNBqaubSvBB6f2GUXw'  # Replace with your actual API key

# Define the 16 features you need
FEATURES = [
    "Page Reputation Score", "Phishing Detection", "Malware Detection",
    "SSL/TLS Status", "Domain Age", "Hosting Provider Reputation",
    "Content Authenticity", "Redirection Analysis", "Suspicious Links",
    "Contact Information Verification", "Social Media Presence",
    "Privacy Policy Presence", "Terms of Service Presence",
    "Cookie Policy Detection", "Trustworthiness Score", "User Reviews and Ratings"
]

def analyze_url(url):
    # Make request to Gemini AI API with necessary parameters
    api_key = os.getenv('GOOGLE_API_KEY')
    api_url = f"https://gemini.googleapis.com/v1/analyze?url={url}&features={','.join(FEATURES)}&key={api_key}"
    
    response = requests.get(api_url)
    
    if response.status_code != 200:
        return {"error": "API request failed", "status_code": response.status_code}
    
    data = response.json()

    # Parse the data to ensure each feature is handled
    analysis_results = {feature: data.get(feature, "Not Available") for feature in FEATURES}
    
    # Example processing for demonstration purposes
    return {
        "url": url,
        "analysis_results": analysis_results
    }

@app.route('/analyze', methods=['POST'])
def analyze():
    try:
        # Get the data from the request
        request_data = request.get_json()
        url = request_data.get('url')
        
        if not url:
            return jsonify({"error": "URL is required"}), 400
        
        # Call the analyze_url function
        analysis = analyze_url(url)
        
        # Return the analysis result in JSON format
        return jsonify(analysis)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    # Set the host and port
    app.run(host="0.0.0.0", port=5000, debug=True)
