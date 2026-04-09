"""
WAF Proxy Gateway - 3-Layer Security Architecture

Traffic Flow:
Internet → Layer 1 (Fast) → Layer 2 (Pattern) → Layer 3 (AI) → Target Website
"""

import os
import logging
import asyncio
import httpx
from fastapi import FastAPI, Request, Response, HTTPException
from fastapi.responses import JSONResponse
from datetime import datetime
from typing import Dict, Optional

from layer1_defense import Layer1Defense
from layer2_patterns import Layer2PatternMatcher

# Logging setup
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# ==================== CONFIGURATION ====================

class Config:
    # Redis connection
    REDIS_HOST = os.getenv('REDIS_HOST', 'localhost')
    REDIS_PORT = int(os.getenv('REDIS_PORT', 6379))
    
    # Target website to protect
    TARGET_WEBSITE = os.getenv('TARGET_WEBSITE', 'http://example.com')
    
    # AI Server for Layer 3
    AI_SERVER_URL = os.getenv('AI_SERVER_URL', 'http://localhost:8000')
    
    # Layer toggles
    LAYER1_ENABLED = os.getenv('LAYER1_ENABLED', 'true').lower() == 'true'
    LAYER2_ENABLED = os.getenv('LAYER2_ENABLED', 'true').lower() == 'true'
    LAYER3_ENABLED = os.getenv('LAYER3_ENABLED', 'false').lower() == 'true'  # AI layer off by default
    
    # Security settings
    LAYER3_ASYNC = True  # Async mode: AI analyzes in background, feeds results to Layer 1 & 2
    LOG_ALL_REQUESTS = True
    INCLUDE_RULE_INFO = False  # Don't expose security rules to attackers


# ==================== INITIALIZE LAYERS ====================

app = FastAPI(
    title="WAF Security Gateway",
    description="3-Layer Web Application Firewall",
    version="1.0.0"
)

# Layer 1: Fast checks (Redis)
layer1 = Layer1Defense(
    redis_host=Config.REDIS_HOST,
    redis_port=Config.REDIS_PORT
) if Config.LAYER1_ENABLED else None

# Layer 2: Pattern matching (with Redis for AI-learned patterns)
layer2 = Layer2PatternMatcher(
    rules_file="rules/layer2_rules.json",
    redis_client=layer1.redis if layer1 else None
) if Config.LAYER2_ENABLED else None

# HTTP client for forwarding requests with optimized connection pooling
limits = httpx.Limits(max_keepalive_connections=200, max_connections=1000)
http_client = httpx.AsyncClient(
    timeout=30.0,
    follow_redirects=True,
    limits=limits
)


# ==================== MIDDLEWARE ====================

@app.middleware("http")
async def security_gateway(request: Request, call_next):
    """
    Main security middleware - processes every request through 3 layers
    """
    client_ip = request.client.host
    start_time = datetime.now()
    
    logger.info(f"📥 {request.method} {request.url.path} from {client_ip}")
    
    # ============ LAYER 1: FAST CHECKS ============
    if layer1 and Config.LAYER1_ENABLED:
        # Check whitelist first
        if layer1.is_whitelisted(client_ip):
            logger.info(f"✅ {client_ip} is whitelisted - bypass all checks")
            return await call_next(request)
        
        # Check blocklist
        if layer1.is_blocked(client_ip):
            logger.warning(f"🚫 BLOCKED by Layer 1: {client_ip}")
            return JSONResponse(
                status_code=403,
                content={
                    "error": "Access denied",
                    "message": "Your IP has been blocked"
                }
            )
        
        # Check rate limit
        allowed, rate_info = layer1.check_rate_limit(client_ip)
        if not allowed:
            logger.warning(f"⏱️  RATE LIMITED: {client_ip} ({rate_info['current']}/{rate_info['limit']})")
            return JSONResponse(
                status_code=429,
                content={
                    "error": "Rate limit exceeded",
                    "limit": rate_info['limit'],
                    "window": f"{rate_info['window']}s",
                    "retry_after": rate_info['retry_after']
                }
            )
    
    # ============ LAYER 2: PATTERN DETECTION ============
    if layer2 and Config.LAYER2_ENABLED:
        # Read request body
        body = None
        if request.method in ['POST', 'PUT', 'PATCH']:
            body = await request.body()
            body = body.decode('utf-8', errors='ignore')
        
        # Analyze request
        is_malicious, threats = layer2.analyze_request(
            method=request.method,
            path=str(request.url.path),
            headers=dict(request.headers),
            body=body,
            query_params=dict(request.query_params)
        )
        
        if is_malicious:
            risk_score = layer2.get_risk_score(threats)
            should_block = layer2.should_block(threats)
            
            # Add reputation strike
            if layer1:
                layer1.add_reputation_strike(client_ip, 'pattern_match')
            
            # Log threat
            logger.error(f"🔥 ATTACK DETECTED from {client_ip}: {layer2.get_block_reason(threats)} (Risk: {risk_score})")
            
            # Block if action is 'block'
            if should_block:
                # Temporary block for 1 hour
                if layer1:
                    layer1.block_ip(
                        client_ip, 
                        f"Layer 2: {layer2.get_block_reason(threats)}",
                        duration_hours=1
                    )
                
                response_content = {
                    "error": "Request blocked by security policy",
                    "risk_score": risk_score
                }
                
                if Config.INCLUDE_RULE_INFO:
                    response_content["threats"] = threats
                
                return JSONResponse(
                    status_code=403,
                    content=response_content
                )
    
    # ============ LAYER 3: AI ANALYSIS (ASYNC) ============
    if Config.LAYER3_ENABLED:
        if Config.LAYER3_ASYNC:
            # Run AI analysis in background (don't block request)
            asyncio.create_task(analyze_with_ai(request, client_ip))
        else:
            # Block and wait for AI analysis
            ai_result = await analyze_with_ai(request, client_ip)
            if ai_result and ai_result.get('is_malicious'):
                logger.error(f"🤖 AI BLOCKED: {client_ip} - {ai_result.get('reason')}")
                return JSONResponse(
                    status_code=403,
                    content={
                        "error": "Suspicious behavior detected",
                        "message": "Your request has been flagged by our AI system"
                    }
                )
    
    # ============ ALL CHECKS PASSED - FORWARD REQUEST ============
    response = await call_next(request)
    
    # Log response time
    duration = (datetime.now() - start_time).total_seconds()
    logger.info(f"✅ {request.method} {request.url.path} → {response.status_code} ({duration:.2f}s)")
    
    return response


# ==================== LAYER 3: AI ANALYSIS ====================

async def analyze_with_ai(request: Request, client_ip: str) -> Optional[Dict]:
    """
    Send request to AI server for deep analysis.
    When threats are found, feeds back into Layer 1 (block IP) and Layer 2 (learn pattern).
    """
    try:
        # Prepare payload
        body = None
        if request.method in ['POST', 'PUT', 'PATCH']:
            body = await request.body()
            body = body.decode('utf-8', errors='ignore')
        
        payload = {
            "method": request.method,
            "path": str(request.url.path),
            "headers": dict(request.headers),
            "body": body,
            "client_ip": client_ip
        }
        
        # Send to AI server
        async with httpx.AsyncClient(timeout=5.0) as client:
            response = await client.post(
                f"{Config.AI_SERVER_URL}/analyze",
                json=payload
            )
            
            if response.status_code == 200:
                result = response.json()
                
                if result.get('is_malicious'):
                    threat_type = result.get('threat_type', 'unknown')
                    reason = result.get('reason', 'AI detected threat')
                    confidence = result.get('confidence', 0.0)
                    
                    logger.warning(
                        f"🤖 AI DETECTED THREAT from {client_ip}: "
                        f"{reason} (type={threat_type}, confidence={confidence:.2f})"
                    )
                    
                    # ===== FEEDBACK TO LAYER 1: Block this attacker =====
                    if layer1:
                        # Add heavy reputation strike
                        layer1.add_reputation_strike(client_ip, 'ai_flagged')
                        
                        # If confidence is high enough, block IP immediately
                        if confidence >= 0.7:
                            layer1.block_ip(
                                client_ip,
                                f"AI Layer 3: {reason} (confidence: {confidence:.2f})",
                                duration_hours=2
                            )
                            logger.warning(
                                f"🔒 AI → Layer 1: Blocked IP {client_ip} for 2h "
                                f"(confidence: {confidence:.2f})"
                            )
                    
                    # ===== FEEDBACK TO LAYER 2: Store learned pattern =====
                    if layer1 and body:
                        # Store the malicious payload in Redis so Layer 2 can
                        # check against dynamic (AI-learned) patterns
                        import json as json_module
                        learned_pattern = {
                            'source': 'ai_layer3',
                            'threat_type': threat_type,
                            'method': request.method,
                            'path': str(request.url.path),
                            'body_snippet': body[:500] if body else None,
                            'confidence': confidence,
                            'reason': reason,
                            'detected_at': datetime.now().isoformat(),
                            'client_ip': client_ip
                        }
                        layer1.redis.lpush(
                            "ai:learned_patterns",
                            json_module.dumps(learned_pattern)
                        )
                        layer1.redis.ltrim("ai:learned_patterns", 0, 499)
                        
                        logger.info(
                            f"📚 AI → Layer 2: Stored learned pattern "
                            f"(type={threat_type}) for future detection"
                        )
                
                return result
    
    except Exception as e:
        logger.error(f"AI analysis failed: {e}")
        return None


# ==================== PROXY FORWARDING ====================

@app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"])
async def proxy_forward(request: Request, path: str):
    """
    Forward request to target website after security checks
    """
    # Build target URL
    target_url = f"{Config.TARGET_WEBSITE}/{path}"
    if request.url.query:
        target_url += f"?{request.url.query}"
    
    # Prepare headers (remove hop-by-hop headers)
    headers = dict(request.headers)
    headers.pop('host', None)
    headers.pop('content-length', None)
    
    # Read body
    body = await request.body() if request.method in ['POST', 'PUT', 'PATCH'] else None
    
    try:
        # Forward request
        response = await http_client.request(
            method=request.method,
            url=target_url,
            headers=headers,
            content=body
        )
        
        # Return response
        return Response(
            content=response.content,
            status_code=response.status_code,
            headers=dict(response.headers),
            media_type=response.headers.get('content-type')
        )
    
    except Exception as e:
        logger.error(f"Proxy forward error: {e}")
        raise HTTPException(status_code=502, detail="Bad Gateway")


# ==================== ADMIN/MONITORING ENDPOINTS ====================

@app.get("/waf/health")
async def health_check():
    """WAF health check"""
    return {
        "status": "healthy",
        "layers": {
            "layer1": Config.LAYER1_ENABLED,
            "layer2": Config.LAYER2_ENABLED,
            "layer3": Config.LAYER3_ENABLED
        },
        "target": Config.TARGET_WEBSITE
    }


@app.get("/waf/stats")
async def get_stats():
    """Get security statistics"""
    stats = {}
    
    if layer1:
        stats.update(layer1.get_stats())
        stats['top_offenders'] = layer1.get_top_offenders(limit=5)
        stats['recent_attacks'] = layer1.get_recent_attacks(limit=10)
    
    return stats


@app.post("/waf/admin/block/{ip}")
async def admin_block_ip(ip: str, reason: str = "Manual block"):
    """Manually block an IP (requires admin authentication in production)"""
    if not layer1:
        raise HTTPException(status_code=503, detail="Layer 1 not available")
    
    layer1.block_ip(ip, reason, duration_hours=24)
    return {"message": f"IP {ip} has been blocked"}


@app.post("/waf/admin/unblock/{ip}")
async def admin_unblock_ip(ip: str):
    """Manually unblock an IP"""
    if not layer1:
        raise HTTPException(status_code=503, detail="Layer 1 not available")
    
    layer1.unblock_ip(ip)
    return {"message": f"IP {ip} has been unblocked"}


# ==================== STARTUP/SHUTDOWN ====================

@app.on_event("startup")
async def startup_event():
    logger.info("=" * 60)
    logger.info("🛡️  WAF Security Gateway Starting")
    logger.info("=" * 60)
    logger.info(f"Target Website: {Config.TARGET_WEBSITE}")
    logger.info(f"Layer 1 (Fast Checks): {'✓ Enabled' if Config.LAYER1_ENABLED else '✗ Disabled'}")
    logger.info(f"Layer 2 (Patterns): {'✓ Enabled' if Config.LAYER2_ENABLED else '✗ Disabled'}")
    logger.info(f"Layer 3 (AI): {'✓ Enabled' if Config.LAYER3_ENABLED else '✗ Disabled'}")
    logger.info("=" * 60)


@app.on_event("shutdown")
async def shutdown_event():
    await http_client.aclose()
    logger.info("🛡️  WAF Security Gateway Stopped")


# ==================== RUN ====================

if __name__ == "__main__":
    import uvicorn
    
    uvicorn.run(
        "proxy:app",
        host="0.0.0.0",
        port=8080,
        reload=True,
        log_level="info"
    )