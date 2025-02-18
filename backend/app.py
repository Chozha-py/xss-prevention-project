from flask import Flask, request, jsonify
from flask_cors import CORS
from werkzeug.exceptions import BadRequest
import joblib
import nltk
from nltk.tokenize import word_tokenize
import bleach
import os

# Get the absolute path of app.py
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# Corrected model paths
MODEL_PATH = os.path.join(BASE_DIR, "models", "xss_model.pkl")
VECTORIZER_PATH = os.path.join(BASE_DIR, "models", "vectorizer.pkl")

# Ensure model files exist before loading
if not os.path.exists(MODEL_PATH):
    raise FileNotFoundError(f"Model file not found: {MODEL_PATH}")

if not os.path.exists(VECTORIZER_PATH):
    raise FileNotFoundError(f"Vectorizer file not found: {VECTORIZER_PATH}")

# Load pre-trained model and vectorizer
model = joblib.load(MODEL_PATH)
vectorizer = joblib.load(VECTORIZER_PATH)

# Initialize Flask app
app = Flask(__name__)
CORS(app)

@app.route("/")
def home():
    return jsonify({"message": "XSS Detection API is running!"})

@app.route("/detect", methods=["POST"])
def detect_xss():
    try:
        data = request.get_json()
        user_input = data.get("input", "")

        if not user_input:
            raise BadRequest("Input is required.")

        sanitized_input = sanitize_input(user_input)
        is_malicious = predict_xss(user_input)

        return jsonify({
            "input": user_input,
            "sanitized_input": sanitized_input,
            "is_malicious": is_malicious
        })

    except BadRequest as e:
        return jsonify({"error": str(e)}), 400

def sanitize_input(input_text):
    return bleach.clean(input_text)

def predict_xss(input_text):
    tokens = word_tokenize(input_text)
    vectorized_input = vectorizer.transform([" ".join(tokens)])
    prediction = model.predict(vectorized_input)
    return bool(prediction[0])

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)