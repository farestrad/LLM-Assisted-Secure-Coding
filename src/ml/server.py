from flask import Flask, request, jsonify
import requests
import joblib
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer

app = Flask(__name__)

print("Loading trained model and vectorizer...")
model = joblib.load("trained_model.pkl")  
vectorizer = joblib.load("vectorizer.pkl")

df = pd.read_csv("cwe_dataset.csv")
cwe_mapping = dict(zip(df["CWE"], df["Description"]))

OLLAMA_API = "http://127.0.0.1:11434/api/generate"

@app.route('/generate', methods=['POST'])
def generate_and_finetune():
    data = request.json
    model_name = data.get('model', 'llama3')
    prompt = data.get('prompt', '')

    # Send prompt to LLaMA 3 via Ollama
    response = requests.post(OLLAMA_API, json={
        "model": model_name,
        "prompt": prompt,
        "stream": False
    })

    if response.status_code != 200:
        return jsonify({"error": "LLaMA 3 failed to generate."}), 500

    raw_output = response.json().get('response', '')
    print("Raw Output from LLaMA 3:", raw_output)

    # Step 1: Fine-tune the generated code using shadow ML
    fine_tuned_code = fine_tune_output(raw_output)

    # Step 2: Run CWE prediction on the fine-tuned code
    cwe_result = predict_cwe(fine_tuned_code)

    # Return fine-tuned code and CWE prediction
    return jsonify({
        "fine_tuned_code": fine_tuned_code,
        "cwe_result": cwe_result
    })


def fine_tune_output(code):
    fine_tuned_code = f"/* Fine-Tuned Code */\n{code}"
    return fine_tuned_code

@app.route('/predict', methods=['POST'])
def predict():
    data = request.json
    if not data or "text" not in data:
        return jsonify({"error": "No code provided"}), 400

    return predict_cwe(data["text"])


def predict_cwe(code_snippet):
    try:
        # Transform code snippet using vectorizer
        features = vectorizer.transform([code_snippet])

        # Predict CWE
        predicted_cwe = model.predict(features)[0]
        cwe_description = cwe_mapping.get(predicted_cwe, "Description not available")

        return {
            "predicted_cwe": predicted_cwe,
            "description": cwe_description
        }

    except Exception as e:
        return {"error": str(e)}

if __name__ == '__main__':
    print("Starting Flask server...")
    app.run(host='0.0.0.0', port=3000)


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

