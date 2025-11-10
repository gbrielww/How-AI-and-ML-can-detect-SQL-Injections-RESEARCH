import joblib
from fastapi import FastAPI
from pydantic import BaseModel
import uvicorn
import sys

app = FastAPI(
    title="SQL Injection Detection API",
    description="An API to classify SQL queries as malicious or benign using a 99.68% accurate Random Forest model.",
    version="1.0"
)

try:
    model = joblib.load('rf_model.joblib')
    vectorizer = joblib.load('tfidf_vectorizer.joblib')
    print("✅ Model and vectorizer loaded successfully!")
except FileNotFoundError:
    print("❌ ERROR: Model or vectorizer files not found.")
    print("Make sure 'rf_model.joblib' and 'tfidf_vectorizer.joblib' are in the same folder.")
    sys.exit(1)
except Exception as e:
    print(f"❌ An error occurred loading files: {e}")
    sys.exit(1)

class QueryRequest(BaseModel):
    query: str

class PredictionResponse(BaseModel):
    query: str
    prediction: int
    label: str

@app.post("/detect", response_model=PredictionResponse)
def detect_sql_injection(request: QueryRequest):
    raw_query = request.query
    query_tfidf = vectorizer.transform([raw_query])
    prediction = model.predict(query_tfidf)
    prediction_int = int(prediction[0])
    label = "Malicious" if prediction_int == 1 else "Benign"
    
    return {
        "query": raw_query,
        "prediction": prediction_int,
        "label": label
    }

@app.get("/")
def read_root():
    return {"message": "Welcome to the SQL Injection Detection API. Use the /docs endpoint to see documentation."}

if __name__ == "__main__":
    print("Starting API server on http://127.0.0.1:8000")
    uvicorn.run(app, host="127.0.0.1", port=8000)