import os
import ast
import redis
from fastapi import FastAPI, Request, Header, HTTPException
from pydantic import BaseModel
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

app = FastAPI(title="WAF Dashboard")

# Create templates directory variable
templates = Jinja2Templates(directory="templates")

class Config:
    REDIS_HOST = os.getenv('REDIS_HOST', 'localhost')
    REDIS_PORT = int(os.getenv('REDIS_PORT', 6379))

# Redis connection
def get_redis():
    try:
        r = redis.Redis(
            host=Config.REDIS_HOST,
            port=Config.REDIS_PORT,
            decode_responses=True,
            socket_timeout=2
        )
        r.ping()
        return r
    except Exception as e:
        print(f"Redis connection failed: {e}")
        return None

r = get_redis()

@app.get("/", response_class=HTMLResponse)
async def serve_dashboard(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})

@app.get("/api/stats")
async def fetch_stats():
    # If redis connection was lost, try to reconnect
    global r
    if r is None:
        r = get_redis()
    
    if r is None:
        return {"error": "Redis unavailable"}

    try:
        stats = {
            'permanent_blocks': r.scard("blocklist:permanent") or 0,
            'temporary_blocks': len(r.keys("blocklist:temp:*")),
            'active_rate_limits': len(r.keys("ratelimit:*")),
            'total_attacks_logged': int(r.get("stats:total_attacks") or 0)
        }

        # Top Offenders
        offenders = []
        for key in r.scan_iter(match="reputation:*"):
            ip = key.replace("reputation:", "")
            score = int(r.get(key) or 0)
            offenders.append({"ip": ip, "score": score})
        
        offenders.sort(key=lambda x: x["score"], reverse=True)
        stats['top_offenders'] = offenders[:10]

        # Recent Attacks
        recent_raw = r.lrange("attacks:recent", 0, 9)
        recent_parsed = []
        for raw in recent_raw:
            try:
                # Safely parse the string representation of dict
                parsed = ast.literal_eval(raw)
                recent_parsed.append(parsed)
            except Exception:
                continue

        stats['recent_attacks'] = recent_parsed
        
        return stats

    except Exception as e:
        return {"error": str(e)}


class AdminAction(BaseModel):
    ip: str

def verify_admin(authorization: str):
    expected_key = os.getenv('ADMIN_API_KEY')
    if expected_key and authorization != f"Bearer {expected_key}":
        raise HTTPException(status_code=401, detail="Unauthorized")

@app.post("/api/admin/block")
async def block_ip(action: AdminAction, authorization: str = Header(None)):
    verify_admin(authorization)
    if globals().get('r') is None:
        raise HTTPException(status_code=503, detail="Redis unavailable")
    
    pipeline = r.pipeline()
    pipeline.sadd("blocklist:permanent", action.ip)
    pipeline.set(f"block_reason:{action.ip}", "Manual block via Dashboard")
    pipeline.execute()
    return {"status": "success", "message": f"IP {action.ip} blocked permanently."}

@app.post("/api/admin/unblock")
async def unblock_ip(action: AdminAction, authorization: str = Header(None)):
    verify_admin(authorization)
    if globals().get('r') is None:
        raise HTTPException(status_code=503, detail="Redis unavailable")
    
    pipeline = r.pipeline()
    pipeline.srem("blocklist:permanent", action.ip)
    pipeline.delete(f"blocklist:temp:{action.ip}")
    pipeline.delete(f"block_reason:{action.ip}")
    pipeline.execute()
    return {"status": "success", "message": f"IP {action.ip} unblocked and pardoned."}
