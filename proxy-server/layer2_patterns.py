"""
Layer 2 Defense - Pattern-Based Attack Detection
- SQL Injection detection
- XSS attack detection
- Command injection detection
- Path traversal detection
- File upload validation
- Dynamic AI-learned patterns (fed from Layer 3)
"""

import re
import json
import logging
from typing import Dict, List, Tuple, Optional
from pathlib import Path
from difflib import SequenceMatcher

logger = logging.getLogger(__name__)


class Layer2PatternMatcher:
    def __init__(self, rules_file: str = "rules/layer2_rules.json", redis_client=None):
        """Load attack patterns from JSON configuration"""
        self.rules_file = rules_file
        self.patterns = {}
        self.compiled_regex = {}
        self.redis = redis_client  # For AI-learned dynamic patterns
        
        self.load_rules()
        
    def load_rules(self):
        """Load and compile regex patterns from JSON file"""
        try:
            with open(self.rules_file, 'r') as f:
                config = json.load(f)
            
            self.patterns = config.get('patterns', {})
            
            # Compile all regex patterns for performance
            for pattern_name, pattern_data in self.patterns.items():
                if pattern_data.get('enabled', True):
                    regex_list = pattern_data.get('regex_patterns', [])
                    self.compiled_regex[pattern_name] = [
                        re.compile(regex) for regex in regex_list
                    ]
            
            logger.info(f"✓ Loaded {len(self.patterns)} attack patterns from {self.rules_file}")
            
        except FileNotFoundError:
            logger.error(f"✗ Rules file not found: {self.rules_file}")
            raise
        except json.JSONDecodeError as e:
            logger.error(f"✗ Invalid JSON in rules file: {e}")
            raise

    def analyze_request(self, 
                       method: str,
                       path: str,
                       headers: Dict[str, str],
                       body: Optional[str] = None,
                       query_params: Optional[Dict] = None) -> Tuple[bool, List[Dict]]:
        """
        Analyze HTTP request for malicious patterns
        
        Returns:
            (is_malicious, [detected_threats])
        """
        threats = []
        
        # Combine all request data for analysis
        full_content = self._prepare_content(method, path, headers, body, query_params)
        full_content_upper = full_content.upper()
        
        # Check each enabled pattern
        for pattern_name, pattern_data in self.patterns.items():
            if not pattern_data.get('enabled', True):
                continue
            
            # Check string signatures
            signatures = pattern_data.get('signatures', [])
            for signature in signatures:
                if signature.upper() in full_content_upper:
                    threats.append({
                        'type': pattern_name,
                        'severity': pattern_data['severity'],
                        'risk_score': pattern_data['risk_score'],
                        'category': pattern_data['category'],
                        'matched_signature': signature,
                        'action': pattern_data.get('action', 'log')
                    })
                    logger.warning(f"🚨 Detected {pattern_name}: '{signature}' in request")
            
            # Check regex patterns
            if pattern_name in self.compiled_regex:
                for regex in self.compiled_regex[pattern_name]:
                    match = regex.search(full_content)
                    if match:
                        threats.append({
                            'type': pattern_name,
                            'severity': pattern_data['severity'],
                            'risk_score': pattern_data['risk_score'],
                            'category': pattern_data['category'],
                            'matched_pattern': match.group(0)[:100],  # Truncate long matches
                            'action': pattern_data.get('action', 'log')
                        })
                        logger.warning(f"🚨 Detected {pattern_name} via regex: {match.group(0)[:50]}")
        
        # Special checks
        threats.extend(self._check_user_agent(headers))
        threats.extend(self._check_http_method(method))
        
        # Check AI-learned dynamic patterns from Redis
        threats.extend(self._check_ai_learned_patterns(full_content, body))
        
        is_malicious = len(threats) > 0
        return is_malicious, threats

    def _check_ai_learned_patterns(self, full_content: str, body: Optional[str] = None) -> List[Dict]:
        """
        Check request against patterns learned by AI (Layer 3).
        These are stored in Redis by the AI feedback loop.
        Uses similarity matching to catch variations of known attacks.
        """
        threats = []
        
        if not self.redis or not body:
            return threats
        
        try:
            # Get recent AI-learned patterns from Redis
            learned = self.redis.lrange("ai:learned_patterns", 0, 99)
            
            for pattern_json in learned:
                try:
                    pattern = json.loads(pattern_json)
                    stored_body = pattern.get('body_snippet', '')
                    
                    if not stored_body:
                        continue
                    
                    # Similarity check: catch variations of the same attack
                    similarity = SequenceMatcher(
                        None, body.lower(), stored_body.lower()
                    ).ratio()
                    
                    if similarity >= 0.6:  # 60% similarity threshold
                        threats.append({
                            'type': f"ai_learned_{pattern.get('threat_type', 'unknown')}",
                            'severity': 'critical',
                            'risk_score': 90,
                            'category': 'ai_learned',
                            'matched_pattern': f"Similar to AI-detected attack (similarity: {similarity:.0%})",
                            'original_reason': pattern.get('reason', ''),
                            'action': 'block'
                        })
                        logger.warning(
                            f"🧠 AI-learned pattern matched! "
                            f"Similarity: {similarity:.0%} to previously detected "
                            f"{pattern.get('threat_type', 'unknown')} attack"
                        )
                        break  # One match is enough
                
                except (json.JSONDecodeError, TypeError):
                    continue
        
        except Exception as e:
            logger.error(f"Error checking AI-learned patterns: {e}")
        
        return threats

    def _prepare_content(self, method: str, path: str, headers: Dict, 
                        body: Optional[str], query_params: Optional[Dict]) -> str:
        """Combine all request parts into searchable content"""
        content_parts = [
            method.upper(),
            path,
            str(headers),
            body or "",
            str(query_params or {})
        ]
        return " ".join(content_parts)

    def _check_user_agent(self, headers: Dict) -> List[Dict]:
        """Check for malicious user agents"""
        threats = []
        user_agent = headers.get('User-Agent', '').lower()
        
        if not user_agent:
            return threats
        
        pattern_data = self.patterns.get('malicious_user_agent', {})
        if not pattern_data.get('enabled', True):
            return threats
        
        signatures = pattern_data.get('signatures', [])
        for signature in signatures:
            if signature.lower() in user_agent:
                threats.append({
                    'type': 'malicious_user_agent',
                    'severity': pattern_data['severity'],
                    'risk_score': pattern_data['risk_score'],
                    'category': pattern_data['category'],
                    'matched_signature': signature,
                    'user_agent': user_agent,
                    'action': pattern_data.get('action', 'block')
                })
                logger.warning(f"🚨 Malicious User-Agent detected: {signature}")
        
        return threats

    def _check_http_method(self, method: str) -> List[Dict]:
        """Check for dangerous HTTP methods"""
        threats = []
        
        pattern_data = self.patterns.get('http_method_abuse', {})
        if not pattern_data.get('enabled', True):
            return threats
        
        blocked_methods = pattern_data.get('blocked_methods', [])
        if method.upper() in blocked_methods:
            threats.append({
                'type': 'http_method_abuse',
                'severity': pattern_data['severity'],
                'risk_score': pattern_data['risk_score'],
                'category': pattern_data['category'],
                'method': method,
                'action': pattern_data.get('action', 'block')
            })
            logger.warning(f"🚨 Blocked HTTP method: {method}")
        
        return threats

    def check_file_upload(self, filename: str, content_type: str) -> Tuple[bool, Optional[Dict]]:
        """
        Validate file upload for malicious extensions
        
        Returns:
            (is_safe, threat_info)
        """
        pattern_data = self.patterns.get('suspicious_file_upload', {})
        if not pattern_data.get('enabled', True):
            return True, None
        
        # Check file extension
        file_ext = Path(filename).suffix.lower()
        dangerous_exts = pattern_data.get('file_extensions', [])
        
        if file_ext in dangerous_exts:
            threat = {
                'type': 'suspicious_file_upload',
                'severity': pattern_data['severity'],
                'risk_score': pattern_data['risk_score'],
                'category': pattern_data['category'],
                'filename': filename,
                'extension': file_ext,
                'action': pattern_data.get('action', 'block')
            }
            logger.warning(f"🚨 Dangerous file upload blocked: {filename}")
            return False, threat
        
        return True, None

    def get_risk_score(self, threats: List[Dict]) -> int:
        """Calculate total risk score from detected threats"""
        if not threats:
            return 0
        
        # Take the highest risk score
        max_score = max(t['risk_score'] for t in threats)
        
        # Add 10% for each additional threat
        multiplier = 1.0 + (len(threats) - 1) * 0.1
        
        total_score = min(100, int(max_score * multiplier))
        return total_score

    def should_block(self, threats: List[Dict]) -> bool:
        """Determine if request should be blocked based on threats"""
        for threat in threats:
            if threat.get('action') == 'block':
                return True
        return False

    def get_block_reason(self, threats: List[Dict]) -> str:
        """Generate human-readable block reason"""
        if not threats:
            return "Unknown"
        
        # Group by type
        threat_types = {}
        for threat in threats:
            t_type = threat['type']
            threat_types[t_type] = threat_types.get(t_type, 0) + 1
        
        # Format reason
        reasons = [f"{count}x {t_type}" for t_type, count in threat_types.items()]
        return "Detected: " + ", ".join(reasons)


# ==================== USAGE EXAMPLE ====================

if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )
    
    # Initialize
    matcher = Layer2PatternMatcher(rules_file="layer2_rules.json")
    
    # Test SQL injection
    print("\n=== Test 1: SQL Injection ===")
    is_mal, threats = matcher.analyze_request(
        method="GET",
        path="/api/users?id=1' OR '1'='1",
        headers={"User-Agent": "Mozilla/5.0"},
        body=None,
        query_params={"id": "1' OR '1'='1"}
    )
    print(f"Malicious: {is_mal}")
    print(f"Threats: {threats}")
    print(f"Risk Score: {matcher.get_risk_score(threats)}")
    print(f"Should Block: {matcher.should_block(threats)}")
    
    # Test XSS
    print("\n=== Test 2: XSS Attack ===")
    is_mal, threats = matcher.analyze_request(
        method="POST",
        path="/comment",
        headers={"User-Agent": "Mozilla/5.0"},
        body='{"comment": "<script>alert(1)</script>"}',
        query_params=None
    )
    print(f"Malicious: {is_mal}")
    print(f"Threats: {threats}")
    
    # Test file upload
    print("\n=== Test 3: File Upload ===")
    is_safe, threat = matcher.check_file_upload("shell.php", "application/x-php")
    print(f"Safe: {is_safe}")
    print(f"Threat: {threat}")
    
    # Test clean request
    print("\n=== Test 4: Clean Request ===")
    is_mal, threats = matcher.analyze_request(
        method="GET",
        path="/api/products",
        headers={"User-Agent": "Mozilla/5.0"},
        body=None,
        query_params={"page": "1"}
    )
    print(f"Malicious: {is_mal}")
    print(f"Threats: {threats}")