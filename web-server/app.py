import os
from functools import wraps
from flask import Flask, jsonify, request
from security import Layer1Defense

app = Flask(__name__)
defense = Layer1Defense()

ADMIN_API_KEY = os.environ.get('ADMIN_API_KEY')
if not ADMIN_API_KEY:
    raise RuntimeError("ADMIN_API_KEY environment variable is required")

def require_admin(f):
    """Decorator that protects admin routes with an API key."""
    @wraps(f)
    def decorated(*args, **kwargs):
        key = request.headers.get('X-Admin-Key')
        if key != ADMIN_API_KEY:
            return jsonify({"error": "Unauthorized"}), 401
        return f(*args, **kwargs)
    return decorated

@app.before_request
def security_check():
    """Layer 1 security gate — runs before every request."""
    ip = request.remote_addr

    # 1. Check blocklist first (fastest check)
    if defense.is_blocked(ip):
        return jsonify({
            "error": "Access denied",
            "reason": "Your IP has been blocked"
        }), 403

    # 2. Check rate limit
    if not defense.check_rate_limit(ip):
        defense.track_suspicious_activity(ip, "rate_limit_exceeded")
        return jsonify({
            "error": "Rate limit exceeded",
            "reason": f"Max {defense.max_requests} requests per {defense.window_seconds}s"
        }), 429

# --- Routes ---

@app.route('/')
def home():
    return jsonify({
        "message": "Web server is running!",
        "status": "ok"
    })

@app.route('/health')
def health():
    return jsonify({"status": "healthy"})

# --- Admin/Debug Routes ---

@app.route('/admin/block/<ip_address>', methods=['POST'])
@require_admin
def admin_block(ip_address):
    """Manually block an IP."""
    defense.block_ip(ip_address)
    return jsonify({"message": f"IP {ip_address} has been blocked"})

@app.route('/admin/reputation/<ip_address>')
@require_admin
def admin_reputation(ip_address):
    """Check the reputation score of an IP."""
    score = defense.get_reputation_score(ip_address)
    blocked = defense.is_blocked(ip_address)
    return jsonify({
        "ip": ip_address,
        "reputation_score": score,
        "is_blocked": blocked
    })

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False)