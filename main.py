from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import os
from dotenv import load_dotenv

load_dotenv()

app = FastAPI(title="AI-Based Junior SOC Analyst")

class LogEntry(BaseModel):
    log_content: str

@app.get("/")
async def root():
    return {"message": "Welcome to the AI-Based Junior SOC Analyst API"}

@app.post("/analyze")
async def analyze_log(entry: LogEntry):
    # Placeholder for AI analysis logic
    return {
        "analysis": "This is a placeholder analysis for the provided log content.",
        "risk_level": "Low",
        "suggestions": ["Monitor for further activity", "Check source IP reputation"]
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
