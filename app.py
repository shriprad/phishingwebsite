import os
import requests
from flask import Flask, render_template, request, jsonify

app = Flask(__name__)

# Set your Google API Key from environment variables
API_KEY = os.environ.get('AIzaSyDPoaPx17CL68O0xhNBqaubSvBB6f2GUXw')
GEMINI_API_ENDPOINT = "https://gemini.googleapis.com/v1/url:analyze"  # Placeholder URL

def analyze_url(url, features):
    try:
        # Prepare the payload with URL and features
        payload = {
            "url": url,
            "features": features
        }

        # Make request to Google Gemini API
        response = requests.post(
            GEMINI_API_ENDPOINT,
            headers={
                "Authorization": f"Bearer {API_KEY}",
                "Content-Type": "application/json"
            },
            json=payload
        )

        # Raise an exception if the request failed
        response.raise_for_status()

        # Parse the response data
        data = response.json()
        justification = data.get('justification', 'No analysis result available')
        
        return justification
    
    except requests.exceptions.RequestException as e:
        return f"Error analyzing URL: {str(e)}"

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/analyze', methods=['POST'])
def analyze():
    url = request.form['url']
    # Collecting all 16 features from the form data
    features = {
        "feature1": request.form.get('feature1'),
        "feature2": request.form.get('feature2'),
        "feature3": request.form.get('feature3'),
        "feature4": request.form.get('feature4'),
        "feature5": request.form.get('feature5'),
        "feature6": request.form.get('feature6'),
        "feature7": request.form.get('feature7'),
        "feature8": request.form.get('feature8'),
        "feature9": request.form.get('feature9'),
        "feature10": request.form.get('feature10'),
        "feature11": request.form.get('feature11'),
        "feature12": request.form.get('feature12'),
        "feature13": request.form.get('feature13'),
        "feature14": request.form.get('feature14'),
        "feature15": request.form.get('feature15'),
        "feature16": request.form.get('feature16'),
    }
    
    justification = analyze_url(url, features)
    return jsonify({"result": justification})

if __name__ == "__main__":
    app.run(debug=True)
