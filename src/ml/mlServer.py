from flask import Flask, request, jsonify
import joblib
import numpy as np

app = Flask(__name__)

# Load the trained model and vectorizer
model = joblib.load("trained_model.pkl")
vectorizer = joblib.load("vectorizer.pkl")

@app.route("/predict", methods=["POST"])
def predict():
    data = request.get_json()
    if not data or "text" not in data:
        return jsonify({"error": "No text provided"}), 400

    try:
        # Transform the input text using the loaded vectorizer
        text_input = data["text"]
        features = vectorizer.transform([text_input])
        prediction = model.predict(features)[0]
        return jsonify({"predicted_cwe": prediction})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == "__main__":
    app.run(host=127.0.0.1, port=3000)

# import joblib

# # Load model and vectorizer
# model = joblib.load("trained_model.pkl")
# vectorizer = joblib.load("vectorizer.pkl")

# # Allow user to input multiple texts
# print("Enter vulnerability descriptions (type 'exit' to stop):")
# user_texts = []
# while True:
#     text = input("Enter a description: ")
#     if text.lower() == "exit":
#         break
#     user_texts.append(text)

# # Convert texts into numerical features
# features = vectorizer.transform(user_texts)

# # Make predictions
# predictions = model.predict(features)

# # Print predictions
# for text, cwe in zip(user_texts, predictions):
#     print(f"Text: {text}\nPredicted CWE: {cwe}\n")

