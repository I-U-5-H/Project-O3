import os
import re
import json
import ollama
from google import genai
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
from pydantic import BaseModel

try:
    from config import GEMINI_API_KEY
except ImportError:
    GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "")

if not GEMINI_API_KEY:
    print("WARNING: GEMINI_API_KEY missing in config.py or environment variables")

client = genai.Client(api_key=GEMINI_API_KEY)

app = FastAPI()

privacy_map = {}

# Enhanced REGEX
def regex_detector(text):
    pii = {}
    # Email
    for e in re.findall(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b', text): pii[e] = "EMAIL"
    
    # Password style
    for p in re.findall(r'(?i)(?:password|pwd|pass)\s*[:=]\s*([^\s]+)', text): pii[p] = "PASSWORD"
    
    # GitHub
    for g in re.findall(r'ghp_[A-Za-z0-9]{36}', text): pii[g] = "GITHUB_TOKEN"
    for g in re.findall(r'(?i)(?:github_pat|github_oauth)_[a-zA-Z0-9_]{30,100}', text): pii[g] = "GITHUB_TOKEN"
    
    # AWS
    for a in re.findall(r'(?<![A-Z0-9])[A-Z0-9]{20}(?![A-Z0-9])', text):
        if a.startswith("AKIA"):
            pii[a] = "AWS_ACCESS_KEY"
            
    # Credit Card (basic formatting)
    for c in re.findall(r'(?:\d[ -]*?){13,16}', text): 
        # Simple heuristic to avoid matching non-space separated long numbers that aren't CC
        clean_c = c.replace('-', '').replace(' ', '')
        if 13 <= len(clean_c) <= 16:
            pii[c.strip()] = "CREDIT_CARD"
            
    # Phone number (basic pattern)
    for ph in re.findall(r'(?:(?:\+?1\s*(?:[.-]\s*)?)?(?:\(\s*([2-9]1[02-9]|[2-9][02-8]1|[2-9][02-8][02-9])\s*\)|([2-9]1[02-9]|[2-9][02-8]1|[2-9][02-8][02-9]))\s*(?:[.-]\s*)?)?([2-9]1[02-9]|[2-9][02-9]1|[2-9][02-9]{2})\s*(?:[.-]\s*)?([0-9]{4})(?:\s*(?:#|x\.?|ext\.?|extension)\s*(\d+))?', text):
        matched_str = "".join([m for m in ph if m])
        if len(matched_str) >= 10:
             continue # skipping phone numbers for now due to regex complexity. We'll rely on LLM for phones mostly or generic secrets.
    
    # Generic Secret (high entropy >= 15 chars)
    for s in re.findall(r'\b(?=.*[A-Za-z])(?=.*[0-9])[A-Za-z0-9@#$%^&+=_!]{15,}\b', text):
        if s not in pii: pii[s] = "SECRET"
    
    return pii

# Enhanced OLLAMA Engine
def ollama_detector(text):
    prompt = f"""You are a strict data loss prevention (DLP) engine.
Extract ALL distinct sensitive values from the given text.

RULES:
- Return ONLY a raw JSON object. NO markdown fences. NO introductory text. NO explanation. NO conversational text.
- Format: {{"exact_value_found_in_text": "CATEGORY"}}
- Categories: EMAIL, PASSWORD, API_KEY, TOKEN, SECRET, PHONE, CREDIT_CARD, PII, SSN

If no sensitive data is found, output: {{}}

Text to analyze:
{text}
"""
    try:
        response = ollama.chat(
            model="llama3.1:8b",
            messages=[{"role": "user", "content": prompt}],
            options={"temperature": 0, "top_p": 0.9}
        )
        raw_output = response["message"]["content"].strip()
        cleaned = raw_output.replace("```json", "").replace("```", "").strip()
        json_match = re.search(r'\{[\s\S]*?\}', cleaned)
        if not json_match: return {}
        parsed = json.loads(json_match.group())
        return {k.strip(): str(v).upper().strip() for k, v in parsed.items()}
    except Exception as e:
        print("Ollama Parsing Error:", e)
        return {}

def combine(regex_pii, llm_pii):
    combined = regex_pii.copy()
    for key, value in llm_pii.items():
        combined[key] = value
    return combined

def mask(text, pii):
    global privacy_map
    privacy_map = {}
    masked = text
    counters = {}
    
    # Find all secrets sorted by length (longest first to avoid partial replacements)
    sorted_pii = sorted(pii.items(), key=lambda x: len(x[0]), reverse=True)
    
    for secret, category in sorted_pii:
        if category not in counters: counters[category] = 1
        placeholder = f"<<{category}_{counters[category]}>>"
        counters[category] += 1
        
        # Use regex to replace exact literal string
        pattern = re.escape(secret)
        masked = re.sub(pattern, placeholder, masked)
        privacy_map[placeholder] = secret
        
    return masked

def cloud_ai(masked_text):
    try:
        response = client.models.generate_content(
            model="gemini-2.5-flash",
            contents=masked_text
        )
        return response.text or ""
    except Exception as e:
        return f"[Cloud Error]: {str(e)}"

def unmask(text):
    final = text
    sorted_map = sorted(privacy_map.items(), key=lambda x: len(x[0]), reverse=True)
    for placeholder, secret in sorted_map:
        final = final.replace(placeholder, secret)
    return final

def secure_prompt_pipeline(user_input):
    regex_pii = regex_detector(user_input)
    llm_pii = ollama_detector(user_input)
    combined_pii = combine(regex_pii, llm_pii)
    masked = mask(user_input, combined_pii)
    cloud_response = cloud_ai(masked)
    final_output = unmask(cloud_response)
    
    return {
        "regex_detected": regex_pii,
        "llm_detected": llm_pii,
        "combined": combined_pii,
        "masked_prompt": masked,
        "cloud_response": cloud_response,
        "final_output": final_output
    }

class ChatRequest(BaseModel):
    message: str

@app.get("/", response_class=HTMLResponse)
async def get_index():
    with open("index.html", "r", encoding="utf-8") as f:
        return f.read()

@app.post("/api/chat")
async def chat_api(request: ChatRequest):
    result = secure_prompt_pipeline(request.message)
    return result

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000)
