import google.generativeai as genai
import os
from flask import Flask, render_template, request

# Set your API Key in Colab
os.environ['GOOGLE_API_KEY'] = 'AIzaSyDPoaPx17CL68O0xhNBqaubSvBB6f2GUXw'
# Configure the Generative AI API
genai.configure(api_key=os.getenv('GOOGLE_API_KEY'))

# Initialize the Flask app
app = Flask(__name__)

# Function to analyze a URL and return justification for phishing suspicion
def analyze_url(url):
    # Remove trailing slashes from the URL if they exist to avoid inconsistency
    url = url.rstrip('/')

    # Start a chat session
    model = genai.GenerativeModel('gemini-pro')
    chat = model.start_chat(history=[])

    # Create a prompt for the analysis
    prompt = f"Is this URL a phishing attempt: {url}?"

    # Send the message and handle the response
    response = chat.send_message(prompt, stream=True)

    # Variable to track justification
    justification = ""

    # Process the response
    for chunk in response:
        if hasattr(chunk, 'text') and chunk.text:
            justification += f"Response: {chunk.text}\n"
        elif hasattr(chunk, 'safety_ratings') and chunk.safety_ratings:
            for rating in chunk.safety_ratings:
                justification += f"Category: {rating.category}, Probability: {rating.probability}\n"

                # Add justification based on the safety category
                if rating.category == 'HARM_CATEGORY_DANGEROUS_CONTENT':
                    if isinstance(rating.probability, str):  # If probability is a string
                        if rating.probability == 'HIGH':
                            justification += "Justification: The content is highly dangerous, indicating a high likelihood of phishing.\n"
                        elif rating.probability == 'MEDIUM':
                            justification += "Justification: The content is moderately dangerous, indicating a moderate likelihood of phishing.\n"
                        elif rating.probability == 'LOW':
                            justification += "Justification: The content is somewhat dangerous, but the likelihood of phishing is low.\n"
                    elif isinstance(rating.probability, (int, float)):  # If probability is numeric
                        if rating.probability >= 0.75:
                            justification += "Justification: The content has a high probability of being dangerous, indicating a high likelihood of phishing.\n"
                        elif rating.probability >= 0.5:
                            justification += "Justification: The content has a moderate probability of being dangerous, indicating a moderate likelihood of phishing.\n"
                        elif rating.probability >= 0.25:
                            justification += "Justification: The content has a low probability of being dangerous, indicating a lower likelihood of phishing.\n"

                # Handle other suspicious categories
                elif rating.category in ['HARM_CATEGORY_SEXUALLY_EXPLICIT', 'HARM_CATEGORY_HATE_SPEECH', 'HARM_CATEGORY_HARASSMENT']:
                    if isinstance(rating.probability, str):
                        if rating.probability == 'HIGH' or rating.probability == 'MEDIUM':
                            justification += f"Justification: The content is flagged for {rating.category.lower()}, which is suspicious.\n"
                    elif isinstance(rating.probability, (int, float)):
                        if rating.probability >= 0.5:
                            justification += f"Justification: The content is flagged for {rating.category.lower()}, which is suspicious.\n"

    # If no text or safety ratings found
    if not justification:
        justification = "No sufficient information to determine phishing suspicion."

    return justification

# Define the route for the homepage
@app.route("/", methods=["GET", "POST"])
def index():
    justification = ""
    normalized_url = ""  # Variable to hold the normalized URL
    if request.method == "POST":
        url = request.form.get("url")
        normalized_url = url.rstrip('/')  # Normalize the URL
        justification = analyze_url(normalized_url)  # Pass the normalized URL to the analyzer
    return render_template("index.html", justification=justification, normalized_url=normalized_url)

# Run the app
if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000, debug=True)
