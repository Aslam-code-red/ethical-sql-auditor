from fastapi import FastAPI, HTTPException, Security, Depends, Request
from fastapi.security.api_key import APIKeyHeader
from pydantic import BaseModel
from typing import List, Optional
import google.generativeai as genai
from scanner import analyze_sql
import os
from dotenv import load_dotenv

# Import Rate Limiting tools
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

# Load environment variables securely
load_dotenv()

# --- 1. SECURITY CONFIGURATION (The Vault Door) ---
API_KEY_NAME = "X-API-Key"
api_key_header = APIKeyHeader(name=API_KEY_NAME, auto_error=False)

# A database of valid API keys for authorized apps
VALID_API_KEYS = {"audit-key-2026", "new-college-admin"} 

def get_api_key(api_key: str = Security(api_key_header)):
    """Dependency to check if the provided API key is valid."""
    if api_key not in VALID_API_KEYS:
        raise HTTPException(
            status_code=401, 
            detail="⛔ UNAUTHORIZED: Invalid or missing API Key. Access Denied."
        )
    return api_key

# --- 2. INITIALIZE API & RATE LIMITER (DDoS Protection) ---
# Tracks users by their IP address
limiter = Limiter(key_func=get_remote_address) 

app = FastAPI(
    title="Ethical SQL Auditor API",
    description="Enterprise RESTful Microservice with Auth, DDoS Protection, & AI Threat Analysis.",
    version="3.0.0"
)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# --- 3. AI THREAT ANALYST CONFIGURATION ---
# Safely fetches the key from your hidden environment variables!
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")

if not GEMINI_API_KEY:
    print("WARNING: GEMINI_API_KEY not found in environment variables.")

genai.configure(api_key=GEMINI_API_KEY)

# Use the correct stable model
ai_model = genai.GenerativeModel('gemini-pro')

def generate_ai_report(query: str) -> str:
    """Sends the malicious query to Gemini AI for a plain-English explanation."""
    prompt = f"""
    Act as a Senior Cybersecurity Database Analyst. 
    I have intercepted this malicious SQL injection attempt: {query}
    In exactly 2 short sentences, explain to a junior developer what this specific attack is trying to achieve. Keep it highly technical but easy to read.
    """
    try:
        response = ai_model.generate_content(prompt)
        return response.text.strip()
    except Exception as e:
        return f"AI Analysis Error: {str(e)}"

# --- 4. DATA MODELS ---
class ScanRequest(BaseModel):
    query: str

class ScanResponse(BaseModel):
    risk_score: int
    status: str
    findings: List[str]
    advice: List[str]
    fixed_code: Optional[str] = None
    ai_analysis: Optional[str] = None  # The new AI field!

# --- 5. ENDPOINTS ---
@app.get("/")
def root_check():
    """Health check endpoint to verify the API is running."""
    return {
        "system_status": "ONLINE", 
        "security": "API Key Required", 
        "rate_limit": "5 requests per minute",
        "ai_module": "Active"
    }

@app.post("/api/v1/scan", response_model=ScanResponse)
@limiter.limit("5/minute") # The Rate Limiter is applied here!
def scan_sql_payload(request: Request, payload: ScanRequest, api_key: str = Depends(get_api_key)):
    """
    Scans a SQL payload. 
    Requires a valid 'X-API-Key' header, is rate-limited, and triggers AI on threats.
    """
    if not payload.query:
        raise HTTPException(status_code=400, detail="Empty SQL query provided.")
    
    # 1. Run the deterministic AST Scanner
    score, findings, advice, fixed_code = analyze_sql(payload.query)
    
    ai_report = None 

    # 2. Determine Status & Trigger AI
    if score == 0:
        status = "SECURE"
        # AI sleeps to save resources on safe queries
    elif score < 50:
        status = "WARNING"
        ai_report = generate_ai_report(payload.query) # Wake up AI!
    else:
        status = "CRITICAL"
        ai_report = generate_ai_report(payload.query) # Wake up AI!
        
    return ScanResponse(
        risk_score=score,
        status=status,
        findings=findings,
        advice=advice,
        fixed_code=fixed_code,
        ai_analysis=ai_report
    )


