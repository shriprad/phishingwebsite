import os
import google.generativeai as genai
from flask import Flask, render_template, request

# Initialize the Flask app
app = Flask(__name__)

# Function to analyze a URL and return justification for phishing suspicion
def analyze_url(url):
    url = url.rstrip('/')  # Ensure the URL doesn't have a trailing slash
    model = genai.GenerativeModel('gemini-pro')  # Assuming gemini-pro is the model used
    chat = model.start_chat(history=[])  # Start the chat with the model
    
    # Create the prompt to check if the URL is phishing
    prompt = f"Is this URL a phishing attempt: {url}?"
    
    # Send the message to the model
    response = chat.send_message(prompt, stream=True)
    
    justification = ""  # Initialize justification string to collect response
    for chunk in response:
        # Check for text in the response and append to justification
        if hasattr(chunk, 'text') and chunk.text:
            justification += f"Response: {chunk.text}\n"
        # If the model returns safety ratings, append them to justification
        elif hasattr(chunk, 'safety_ratings') and chunk.safety_rings:
            for rating in chunk.safety_ratings:
                justification += f"Category: {rating.category}, Probability: {rating.probability}\n"
                if rating.category == 'HARM_CATEGORY_DANGEROUS_CONTENT':
                    justification += "Justification: The content is highly dangerous, indicating a high likelihood of phishing.\n"
    
    # If no justification is generated, return a default response
    if not justification:
        justification = "No sufficient information to determine phishing suspicion."
    
    # Split the justification into lines for rendering in HTML
    justification_lines = justification.split("\n")
    return justification_lines

@app.route("/", methods=["GET", "POST"])
def index():
    justification = None  # Initialize justification to None
    normalized_url = None  # Initialize normalized_url to None
    
    # Handle form submission
    if request.method == "POST":
        url = request.form["url"]  # Get URL from the form input
        justification = analyze_url(url)  # Analyze the URL for phishing suspicion
        normalized_url = url  # Set the normalized URL for display
    
    # Render the HTML template with justification and URL
    return render_template("index.html", justification=justification, normalized_url=normalized_url)

if __name__ == "__main__":
    app.run(debug=True)
