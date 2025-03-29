import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
import joblib
import os

# Load datasets
df1 = pd.read_csv("LLMSecEval-Prompts_dataset.csv")
df2 = pd.read_csv("cwe_dataset.csv")

# Ensure the required columns exist in both datasets
if "Description" in df1.columns and "Code" in df1.columns and "CWE" in df1.columns:
    df1["text"] = df1["Description"] + " " + df1["Code"]
    X1 = df1["text"]
    y1 = df1["CWE"]
else:
    raise ValueError("Missing required columns in LLMSecEval-Prompts_dataset.csv")

if "Description" in df2.columns and "Code" in df2.columns and "CWE" in df2.columns:
    df2["text"] = df2["Description"] + " " + df2["Code"]
    X2 = df2["text"]
    y2 = df2["CWE"]
else:
    raise ValueError("Missing required columns in cwe_dataset.csv")

# Combine both datasets
X = pd.concat([X1, X2], ignore_index=True)
y = pd.concat([y1, y2], ignore_index=True)

# Convert text into numerical features
vectorizer = TfidfVectorizer()
X_tfidf = vectorizer.fit_transform(X)

# Split the dataset into training (70%) and testing (30%) sets
X_train, X_test, y_train, y_test = train_test_split(X_tfidf, y, test_size=0.3, random_state=42)

# Create and train the Random Forest model
rf_model = RandomForestClassifier(n_estimators=100, random_state=42)
rf_model.fit(X_train, y_train)

# Evaluate the model on the test set
y_pred = rf_model.predict(X_test)
print(classification_report(y_test, y_pred))

# Save the trained model and the vectorizer
print("Saving trained model...")
joblib.dump(rf_model, "trained_model.pkl")
joblib.dump(vectorizer, "vectorizer.pkl")
print("Model saved successfully!")

# Check if files exist
if os.path.exists("/mnt/data/trained_model.pkl"):
    print("trained_model.pkl successfully created!")
else:
    print("Error: trained_model.pkl NOT created!")