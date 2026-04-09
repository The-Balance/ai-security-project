import os
import ast
import uuid
import redis
from fastapi import FastAPI, Request, Header, HTTPException, Cookie, Response, Depends
from pydantic import BaseModel
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

app = FastAPI(title="WAF Dashboard")

# Create templates directory variable
templates = Jinja2Templates(directory="templates")

class Config:
    REDIS_HOST = os.getenv('REDIS_HOST', 'localhost')
    REDIS_PORT = int(os.getenv('REDIS_PORT', 6379))
    ADMIN_PASSWORD = os.getenv('ADMIN_PASSWORD')

SECRET_TOKEN = str(uuid.uuid4())

def verify_session(session_token: str = Cookie(None)):
    if session_token != SECRET_TOKEN:
        raise HTTPException(status_code=401, detail="Unauthorized")
    return True

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

@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    return templates.TemplateResponse("login.html", {"request": request})

class LoginData(BaseModel):
    password: str

@app.post("/login")
async def do_login(data: LoginData, response: Response):
    if data.password == Config.ADMIN_PASSWORD:
        response.set_cookie(key="session_token", value=SECRET_TOKEN, httponly=True)
        return {"status": "success"}
    raise HTTPException(status_code=401, detail="Invalid password")

@app.post("/logout")
async def do_logout(response: Response):
    response.delete_cookie("session_token")
    return {"status": "success"}

@app.get("/", response_class=HTMLResponse)
async def serve_dashboard(request: Request, session_token: str = Cookie(None)):
    if session_token != SECRET_TOKEN:
        return RedirectResponse(url="/login")
    return templates.TemplateResponse("index.html", {"request": request})

@app.get("/api/stats")
async def fetch_stats(session_token: str = Cookie(None)):
    if session_token != SECRET_TOKEN:
        return {"error": "Unauthorized"}
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
        
        # Details for Active Blocks
        active_blocks = []
        for key in r.keys("blocklist:temp:*"):
            ip = key.replace("blocklist:temp:", "")
            reason = r.get(key)
            ttl = r.ttl(key)
            active_blocks.append({"ip": ip, "reason": reason, "ttl": ttl})
        stats['active_blocks_list'] = active_blocks

        # Details for Permanent Blocks
        permanent_blocks = []
        for ip in r.smembers("blocklist:permanent"):
            reason = r.get(f"block_reason:{ip}")
            permanent_blocks.append({"ip": ip, "reason": reason})
        stats['permanent_blocks_list'] = permanent_blocks
        
        return stats

    except Exception as e:
        return {"error": str(e)}


class AdminAction(BaseModel):
    ip: str

@app.post("/api/admin/block")
async def block_ip(action: AdminAction, is_valid: bool = Depends(verify_session)):
    if globals().get('r') is None:
        raise HTTPException(status_code=503, detail="Redis unavailable")
    
    pipeline = r.pipeline()
    pipeline.sadd("blocklist:permanent", action.ip)
    pipeline.set(f"block_reason:{action.ip}", "Manual block via Dashboard")
    pipeline.execute()
    return {"status": "success", "message": f"IP {action.ip} blocked permanently."}

@app.post("/api/admin/unblock")
async def unblock_ip(action: AdminAction, is_valid: bool = Depends(verify_session)):
    if globals().get('r') is None:
        raise HTTPException(status_code=503, detail="Redis unavailable")
    
    pipeline = r.pipeline()
    pipeline.srem("blocklist:permanent", action.ip)
    pipeline.delete(f"blocklist:temp:{action.ip}")
    pipeline.delete(f"block_reason:{action.ip}")
    pipeline.execute()
    return {"status": "success", "message": f"IP {action.ip} unblocked and pardoned."}

@app.post("/api/admin/restore_reputation")
async def restore_reputation(action: AdminAction, is_valid: bool = Depends(verify_session)):
    if globals().get('r') is None:
        raise HTTPException(status_code=503, detail="Redis unavailable")
    
    pipeline = r.pipeline()
    # Remove reputation score
    pipeline.delete(f"reputation:{action.ip}")
    # Remove any permanent bans
    pipeline.srem("blocklist:permanent", action.ip)
    # Remove temporary bans & reasons
    pipeline.delete(f"blocklist:temp:{action.ip}")
    pipeline.delete(f"block_reason:{action.ip}")
    # Remove ratelimits explicitly as part of reputation restoration
    pipeline.delete(f"ratelimit:{action.ip}")
    pipeline.execute()
    
    return {"status": "success", "message": f"Reputation and access restored for {action.ip}."}

@app.post("/api/admin/clear_history")
async def clear_history(is_valid: bool = Depends(verify_session)):
    if globals().get('r') is None:
        raise HTTPException(status_code=503, detail="Redis unavailable")
    
    pipeline = r.pipeline()
    pipeline.delete("attacks:recent")
    pipeline.set("stats:total_attacks", 0)
    pipeline.execute()
    return {"status": "success", "message": "Log History and Total Intercepts cleared."}
