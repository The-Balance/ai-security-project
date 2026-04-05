"""
AI Security Server - Layer 3 Deep Analysis
Uses Ollama for intelligent threat detection
"""

import os
import logging
import httpx
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import Optional, Dict, List
from datetime import datetime

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# ==================== CONFIGURATION ====================

class Config:
    OLLAMA_HOST = os.getenv('OLLAMA_HOST', 'http://localhost:11434')
    OLLAMA_MODEL = os.getenv('OLLAMA_MODEL', 'llama3.2')
    REDIS_HOST = os.getenv('REDIS_HOST', 'localhost')
    USE_OLLAMA = os.getenv('USE_OLLAMA', 'false').lower() == 'true'


# ==================== MODELS ====================

class AnalysisRequest(BaseModel):
    method: str
    path: str
    headers: Dict[str, str]
    body: Optional[str] = None
    client_ip: Optional[str] = None


class AnalysisResponse(BaseModel):
    is_malicious: bool
    confidence: float
    reason: str
    threat_type: Optional[str] = None
    recommended_action: str


# ==================== APP ====================

app = FastAPI(
    title="AI Security Analysis Server",
    description="Layer 3 - Deep learning threat detection",
    version="1.0.0"
)


# ==================== HEURISTIC ANALYSIS (Fallback) ====================

class HeuristicAnalyzer:
    """Simple rule-based analysis when AI is not available"""
    
    @staticmethod
    def analyze(request: AnalysisRequest) -> AnalysisResponse:
        """
        Basic heuristic checks
        This runs when Ollama is not available
        """
        suspicious_patterns = [
            # SQL Injection
            "UNION SELECT", "DROP TABLE", "OR 1=1", "' OR ''='",
            
            # XSS
            "<script>", "javascript:", "onerror=", "onload=",
            
            # Command Injection
            "; rm -rf", "| bash", "`cat /etc/passwd`",
            
            # Path Traversal
            "../", "..\\", "/etc/passwd",
        ]
        
        # Combine all request data
        content = f"{request.method} {request.path} {request.body or ''}"
        content_upper = content.upper()
        
        # Check for suspicious patterns
        for pattern in suspicious_patterns:
            if pattern.upper() in content_upper:
                logger.warning(f"🔍 Heuristic detected: {pattern}")
                return AnalysisResponse(
                    is_malicious=True,
                    confidence=0.7,
                    reason=f"Suspicious pattern detected: {pattern}",
                    threat_type="pattern_match",
                    recommended_action="block"
                )
        
        # Check for unusual request characteristics
        if len(request.path) > 500:
            return AnalysisResponse(
                is_malicious=True,
                confidence=0.5,
                reason="Unusually long URL path (possible overflow attempt)",
                threat_type="anomaly",
                recommended_action="log"
            )
        
        # All checks passed
        return AnalysisResponse(
            is_malicious=False,
            confidence=0.8,
            reason="No suspicious patterns detected",
            threat_type=None,
            recommended_action="allow"
        )


# ==================== OLLAMA AI ANALYSIS ====================

class OllamaAnalyzer:
    """AI-powered threat detection using Ollama"""
    
    def __init__(self):
        self.client = httpx.AsyncClient(timeout=30.0)
        self.model = Config.OLLAMA_MODEL
    
    async def analyze(self, request: AnalysisRequest) -> AnalysisResponse:
        """
        Use Ollama LLM to analyze request for threats
        """
        # Build analysis prompt
        prompt = self._build_prompt(request)
        
        try:
            # Call Ollama
            response = await self.client.post(
                f"{Config.OLLAMA_HOST}/api/generate",
                json={
                    "model": self.model,
                    "prompt": prompt,
                    "stream": False,
                    "options": {
                        "temperature": 0.1,  # Low temperature for consistent analysis
                        "num_predict": 200
                    }
                }
            )
            
            if response.status_code != 200:
                logger.error(f"Ollama error: {response.status_code}")
                # Fallback to heuristics
                return HeuristicAnalyzer.analyze(request)
            
            result = response.json()
            ai_response = result.get('response', '')
            
            # Parse AI response
            return self._parse_ai_response(ai_response)
        
        except Exception as e:
            logger.error(f"AI analysis failed: {e}")
            # Fallback to heuristics
            return HeuristicAnalyzer.analyze(request)
    
    def _build_prompt(self, request: AnalysisRequest) -> str:
        """Build analysis prompt for LLM"""
        return f"""You are a cybersecurity expert analyzing HTTP requests for threats.

REQUEST DETAILS:
Method: {request.method}
Path: {request.path}
Headers: {request.headers}
Body: {request.body or 'None'}
Client IP: {request.client_ip or 'Unknown'}

ANALYSIS TASK:
Determine if this request contains malicious intent such as:
- SQL Injection
- Cross-Site Scripting (XSS)
- Command Injection
- Path Traversal
- SSRF (Server-Side Request Forgery)
- Any other attack vectors

RESPOND IN THIS EXACT FORMAT:
MALICIOUS: [YES/NO]
CONFIDENCE: [0.0-1.0]
THREAT_TYPE: [type or NONE]
REASON: [brief explanation]
ACTION: [block/log/allow]

Be concise and direct."""
    
    def _parse_ai_response(self, ai_text: str) -> AnalysisResponse:
        """Parse structured response from AI"""
        try:
            lines = ai_text.strip().split('\n')
            parsed = {}
            
            for line in lines:
                if ':' in line:
                    key, value = line.split(':', 1)
                    parsed[key.strip().lower()] = value.strip()
            
            is_malicious = parsed.get('malicious', 'no').upper() == 'YES'
            confidence = float(parsed.get('confidence', '0.5'))
            threat_type = parsed.get('threat_type', 'unknown')
            reason = parsed.get('reason', 'AI analysis completed')
            action = parsed.get('action', 'log')
            
            if threat_type.upper() == 'NONE':
                threat_type = None
            
            return AnalysisResponse(
                is_malicious=is_malicious,
                confidence=confidence,
                reason=reason,
                threat_type=threat_type,
                recommended_action=action
            )
        
        except Exception as e:
            logger.error(f"Failed to parse AI response: {e}")
            # Return safe default
            return AnalysisResponse(
                is_malicious=False,
                confidence=0.5,
                reason="AI response parsing failed",
                threat_type=None,
                recommended_action="log"
            )


# ==================== GLOBAL ANALYZER ====================

if Config.USE_OLLAMA:
    analyzer = OllamaAnalyzer()
    logger.info("🤖 Using Ollama AI for analysis")
else:
    analyzer = None
    logger.info("🔍 Using heuristic analysis (Ollama disabled)")


# ==================== API ENDPOINTS ====================

@app.post("/analyze", response_model=AnalysisResponse)
async def analyze_request(request: AnalysisRequest):
    """
    Analyze HTTP request for security threats
    """
    start_time = datetime.now()
    
    # Choose analyzer
    if analyzer and Config.USE_OLLAMA:
        result = await analyzer.analyze(request)
    else:
        result = HeuristicAnalyzer.analyze(request)
    
    # Log analysis
    duration = (datetime.now() - start_time).total_seconds()
    logger.info(
        f"{'🔥 THREAT' if result.is_malicious else '✅ CLEAN'} "
        f"{request.client_ip} {request.method} {request.path} "
        f"(confidence: {result.confidence:.2f}, {duration:.2f}s)"
    )
    
    return result


@app.get("/")
def root():
    return {
        "service": "AI Security Analysis",
        "status": "online",
        "using_ollama": Config.USE_OLLAMA,
        "model": Config.OLLAMA_MODEL if Config.USE_OLLAMA else "heuristic"
    }


@app.get("/health")
def health():
    return {
        "status": "healthy",
        "ollama": Config.USE_OLLAMA,
        "timestamp": datetime.now().isoformat()
    }


# ==================== STARTUP ====================

@app.on_event("startup")
async def startup():
    logger.info("=" * 60)
    logger.info("🧠 AI Security Server Starting")
    logger.info("=" * 60)
    logger.info(f"Ollama: {'✓ Enabled' if Config.USE_OLLAMA else '✗ Disabled'}")
    if Config.USE_OLLAMA:
        logger.info(f"Model: {Config.OLLAMA_MODEL}")
        logger.info(f"Host: {Config.OLLAMA_HOST}")
    logger.info("=" * 60)


# ==================== RUN ====================

if __name__ == "__main__":
    import uvicorn
    
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info"
    )