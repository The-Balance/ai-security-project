import redis
import time
import os

class Layer1Defense:
    def __init__(self):
        # Connect to the Redis container using the environment variable
        redis_host = os.environ.get('REDIS_HOST', 'localhost')
        # decode_responses=True automatically converts Redis byte strings to Python strings
        self.redis = redis.Redis(host=redis_host, port=6379, decode_responses=True)
        
        # Configuration for Rate Limiting
        self.window_seconds = 60  # The sliding window timeframe
        self.max_requests = 50    # Max allowed requests per window
        self.reputation_threshold = 100  # If threat score hits 100, auto-block

    # --- IP BLOCKLIST LOGIC ---
    def block_ip(self, ip_address):
        """Adds a malicious IP to the Redis blocklist set."""
        self.redis.sadd("ip_blocklist", ip_address)

    def is_blocked(self, ip_address):
        """Checks if an IP exists in the blocklist. Returns True if blocked."""
        return self.redis.sismember("ip_blocklist", ip_address)

    # --- RATE LIMITING LOGIC (Sliding Window) ---
    def check_rate_limit(self, ip_address):
        """
        Checks if the IP has exceeded the allowed request rate.
        Returns True if the request is ALLOWED, False if it should be BLOCKED.
        """
        current_time = time.time()
        redis_key = f"rate_limit:{ip_address}"

        # 1. Remove old timestamps that fall outside our 60-second window
        window_start = current_time - self.window_seconds
        self.redis.zremrangebyscore(redis_key, 0, window_start)
        
        # 2. Count how many requests are left in the current window
        request_count = self.redis.zcard(redis_key)
        
        # 3. If they hit the limit, deny the request
        if request_count >= self.max_requests:
            return False 
            
        # 4. If they are under the limit, log this new request's timestamp
        self.redis.zadd(redis_key, {str(current_time): current_time})
        
        # 5. Set an expiration so old data doesn't fill up Redis memory
        self.redis.expire(redis_key, self.window_seconds)
        
        return True

    def track_suspicious_activity(self, ip_address, activity_type):
        """
        Tracks suspicious behavior and auto-blocks repeat offenders.
        Returns True if IP should be blocked.
        """
        reputation_key = f"reputation:{ip_address}"
        
        # Increment suspicious activity count
        count = self.redis.incr(reputation_key)
        
        # Set expiry (reputation resets after 1 hour)
        self.redis.expire(reputation_key, 3600)
        
        # Auto-block if they've been suspicious 5+ times
        if count >= 5:
            self.block_ip(ip_address)
            self.redis.set(f"block_reason:{ip_address}", f"Auto-blocked: {count} suspicious activities")
            return True
        
        return False

    def get_reputation_score(self, ip_address):
        """Get current reputation score for an IP."""
        reputation_key = f"reputation:{ip_address}"
        score = self.redis.get(reputation_key)
        return int(score) if score else 0