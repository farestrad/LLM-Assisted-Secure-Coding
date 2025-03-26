import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
import joblib
import os

# Load the dataset exported as CSV
df = pd.read_csv("cwe_dataset.csv")

# Combine the description and code into a single text feature
df["text"] = df["Description"] + " " + df["Code"]

# Use the CWE identifier as the label 
X = df["text"]
y = df["CWE"]

# Convert text into numerical features using TF-IDF
vectorizer = TfidfVectorizer()
X_tfidf = vectorizer.fit_transform(X)

# Split the dataset into training and testing sets
X_train, X_test, y_train, y_test = train_test_split(X_tfidf, y, test_size=0.2, random_state=42)

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

# Check if file exists
if os.path.exists("trained_model.pkl"):
    print("trained_model.pkl successfully created!")
else:
    print("Error: trained_model.pkl NOT created!")
