from fastapi import FastAPI
from pydantic import BaseModel

app = FastAPI(title="AI Security Server")

class Payload(BaseModel):
    method: str
    path: str
    headers: dict
    body: str | None = None

@app.post("/analyze")
async def analyze_request(payload: Payload):
    """
    Layer 2: Request inspection.
    Currently uses heuristic checks. Later, we can inject an LLM (Ollama).
    """
    suspicious_keywords = [
        "DROP TABLE", "UNION SELECT", "1=1", "OR 1=1", 
        "\" OR \"\"=\"", "' OR ''='", "<SCRIPT>"
    ]
    
    content_to_check = f"{payload.path} {payload.body or ''}".upper()
    
    for word in suspicious_keywords:
        if word in content_to_check:
            return {
                "is_malicious": True,
                "reason": f"Suspicious signature detected: {word}"
            }
            
    return {
        "is_malicious": False,
        "reason": "OK"
    }

@app.get("/")
def root():
    return {
        "message": "AI server is running!",
        "status": "ok"
    }

@app.get("/health")
def health():
    return {"status": "healthy"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)