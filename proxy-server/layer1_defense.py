"""
Layer 1 Defense - Fast Security Checks
- IP Blocklist (instant lookup)
- Rate Limiting (sliding window)
- Reputation Scoring
- GeoIP filtering (optional)
"""

import redis
import time
import logging
from typing import Optional, Dict, Tuple

logger = logging.getLogger(__name__)


class Layer1Defense:
    def __init__(self, redis_host: str = 'localhost', redis_port: int = 6379):
        """Initialize Redis connection and configuration"""
        self.redis = redis.Redis(
            host=redis_host, 
            port=redis_port, 
            decode_responses=True,
            socket_connect_timeout=2,
            socket_timeout=2
        )
        
        # Test connection
        try:
            self.redis.ping()
            logger.info(f"✓ Connected to Redis at {redis_host}:{redis_port}")
        except redis.ConnectionError as e:
            logger.error(f"✗ Failed to connect to Redis: {e}")
            raise
        
        # Configuration
        self.config = {
            'rate_limit': {
                'window_seconds': 60,
                'max_requests': 100,  # 100 requests per minute
                'strict_mode': False
            },
            'reputation': {
                'threshold': 100,  # Auto-block at score 100
                'decay_hours': 1,  # Reputation resets after 1 hour
                'strike_increments': {
                    'rate_limit': 10,
                    'pattern_match': 25,
                    'ai_flagged': 50
                }
            },
            'blocklist': {
                'auto_expire_hours': 24  # Auto-unblock after 24h
            }
        }

    # ==================== IP BLOCKLIST ====================
    
    def is_blocked(self, ip: str) -> bool:
        """Check if IP is in permanent or temporary blocklist"""
        # Check permanent blocklist
        if self.redis.sismember("blocklist:permanent", ip):
            logger.warning(f"🚫 IP {ip} found in permanent blocklist")
            return True
        
        # Check temporary blocklist
        if self.redis.get(f"blocklist:temp:{ip}"):
            logger.warning(f"⏰ IP {ip} temporarily blocked")
            return True
        
        return False

    def block_ip(self, ip: str, reason: str, duration_hours: int = None):
        """
        Block an IP address
        - duration_hours=None: Permanent block
        - duration_hours=N: Temporary block for N hours
        """
        if duration_hours is None:
            # Permanent block atomic pipeline
            pipeline = self.redis.pipeline()
            pipeline.sadd("blocklist:permanent", ip)
            pipeline.set(f"block_reason:{ip}", reason)
            pipeline.execute()
            logger.critical(f"🔒 PERMANENTLY blocked IP {ip}: {reason}")
        else:
            # Temporary block
            key = f"blocklist:temp:{ip}"
            self.redis.setex(key, duration_hours * 3600, reason)
            logger.warning(f"⏲️  TEMPORARILY blocked IP {ip} for {duration_hours}h: {reason}")
        
        # Log to attack history
        self._log_attack(ip, reason)

    def unblock_ip(self, ip: str):
        """Remove IP from all blocklists"""
        pipeline = self.redis.pipeline()
        pipeline.srem("blocklist:permanent", ip)
        pipeline.delete(f"blocklist:temp:{ip}")
        pipeline.delete(f"block_reason:{ip}")
        pipeline.execute()
        logger.info(f"✓ Unblocked IP {ip}")

    # ==================== RATE LIMITING ====================
    
    def check_rate_limit(self, ip: str) -> Tuple[bool, Dict]:
        """
        Sliding window rate limiting
        Returns: (is_allowed, info_dict)
        """
        current_time = time.time()
        window = self.config['rate_limit']['window_seconds']
        max_requests = self.config['rate_limit']['max_requests']
        
        key = f"ratelimit:{ip}"
        
        # Atomically remove old entries and count requests in the current window
        pipeline = self.redis.pipeline()
        pipeline.zremrangebyscore(key, 0, window_start)
        pipeline.zcard(key)
        results = pipeline.execute()
        
        request_count = results[1]
        
        if request_count >= max_requests:
            # Rate limit exceeded
            self._increment_reputation(ip, 'rate_limit')
            
            return False, {
                'allowed': False,
                'limit': max_requests,
                'window': window,
                'current': request_count,
                'retry_after': int(window)
            }
        
        # Add current request with auto-cleanup (atomic pipeline)
        pipeline = self.redis.pipeline()
        pipeline.zadd(key, {str(current_time): current_time})
        pipeline.expire(key, window + 10)
        pipeline.execute()
        
        return True, {
            'allowed': True,
            'limit': max_requests,
            'window': window,
            'current': request_count + 1,
            'remaining': max_requests - request_count - 1
        }

    # ==================== REPUTATION SYSTEM ====================
    
    def get_reputation(self, ip: str) -> int:
        """Get current reputation score (0-100+)"""
        score = self.redis.get(f"reputation:{ip}")
        return int(score) if score else 0

    def _increment_reputation(self, ip: str, reason: str):
        """Increase reputation score (higher = more suspicious)"""
        increment = self.config['reputation']['strike_increments'].get(reason, 5)
        
        key = f"reputation:{ip}"
        
        pipeline = self.redis.pipeline()
        pipeline.incrby(key, increment)
        pipeline.expire(key, decay_hours * 3600)
        results = pipeline.execute()
        
        new_score = results[0]
        
        logger.warning(f"⚠️  Reputation +{increment} for {ip} ({reason}): now {new_score}")
        
        # Auto-block if threshold exceeded
        threshold = self.config['reputation']['threshold']
        if new_score >= threshold:
            self.block_ip(
                ip, 
                f"Auto-blocked: reputation score {new_score}",
                duration_hours=24
            )
            return True
        
        return False

    def add_reputation_strike(self, ip: str, reason: str = 'manual'):
        """Manually add a reputation strike"""
        return self._increment_reputation(ip, reason)

    # ==================== STATISTICS ====================
    
    def get_stats(self) -> Dict:
        """Get current system statistics"""
        return {
            'permanent_blocks': self.redis.scard("blocklist:permanent"),
            'temporary_blocks': len(self.redis.keys("blocklist:temp:*")),
            'active_rate_limits': len(self.redis.keys("ratelimit:*")),
            'total_attacks_logged': self.redis.get("stats:total_attacks") or 0
        }

    def get_top_offenders(self, limit: int = 10) -> list:
        """Get IPs with highest reputation scores"""
        pattern = "reputation:*"
        offenders = []
        
        for key in self.redis.scan_iter(match=pattern):
            ip = key.replace("reputation:", "")
            score = int(self.redis.get(key))
            offenders.append((ip, score))
        
        # Sort by score descending
        offenders.sort(key=lambda x: x[1], reverse=True)
        return offenders[:limit]

    # ==================== ATTACK LOGGING ====================
    
    def _log_attack(self, ip: str, reason: str):
        """Log attack to Redis for dashboard"""
        self.redis.incr("stats:total_attacks")
        
        # Store recent attacks (last 100)
        attack_data = {
            'ip': ip,
            'reason': reason,
            'timestamp': time.time()
        }
        self.redis.lpush("attacks:recent", str(attack_data))
        self.redis.ltrim("attacks:recent", 0, 99)  # Keep last 100

    def get_recent_attacks(self, limit: int = 20) -> list:
        """Get recent attack attempts"""
        attacks = self.redis.lrange("attacks:recent", 0, limit - 1)
        return [eval(a) for a in attacks]  # Convert string back to dict

    # ==================== WHITELIST ====================
    
    def add_to_whitelist(self, ip: str, reason: str = "trusted"):
        """Add IP to whitelist (bypass all checks)"""
        self.redis.sadd("whitelist", ip)
        self.redis.set(f"whitelist_reason:{ip}", reason)
        logger.info(f"✓ Added {ip} to whitelist: {reason}")

    def is_whitelisted(self, ip: str) -> bool:
        """Check if IP is whitelisted"""
        return self.redis.sismember("whitelist", ip)

    def remove_from_whitelist(self, ip: str):
        """Remove IP from whitelist"""
        self.redis.srem("whitelist", ip)
        self.redis.delete(f"whitelist_reason:{ip}")
        logger.info(f"✓ Removed {ip} from whitelist")


# ==================== USAGE EXAMPLE ====================

if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )
    
    # Initialize
    defense = Layer1Defense(redis_host='localhost')
    
    # Test IP
    test_ip = "192.168.1.100"
    
    # Check whitelist
    if defense.is_whitelisted(test_ip):
        print(f"✓ {test_ip} is whitelisted")
    
    # Check blocklist
    if defense.is_blocked(test_ip):
        print(f"✗ {test_ip} is blocked")
    
    # Check rate limit
    allowed, info = defense.check_rate_limit(test_ip)
    print(f"Rate limit: {info}")
    
    # Check reputation
    rep = defense.get_reputation(test_ip)
    print(f"Reputation score: {rep}")
    
    # Get stats
    stats = defense.get_stats()
    print(f"System stats: {stats}")