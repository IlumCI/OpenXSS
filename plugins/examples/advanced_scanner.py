"""
Advanced XSS Scanner Plugin Example

This plugin demonstrates best practices for OpenXSS plugin development.
It includes:
- Proper error handling
- Resource management
- Configuration validation
- Logging
- Documentation
"""

from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field
import re
import json
from pathlib import Path
from bs4 import BeautifulSoup
from html import unescape

from plugins.base_plugin import BasePlugin, PluginMetadata

@dataclass
class ScanContext:
    """Additional context for the scanner."""
    waf_detected: bool = False
    payloads: List[str] = field(default_factory=list)
    current_parameter: str = None
    successful_payloads: List[str] = field(default_factory=list)
    waf_score: float = 0.0
    total_requests: int = 0
    blocked_requests: int = 0

class AdvancedScanner(BasePlugin):
    """Advanced XSS scanner with WAF detection and payload obfuscation."""
    
    @property
    def metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name="advanced_scanner",
            version="1.0.0",
            author="OpenXSS",
            description="Advanced XSS scanner with WAF detection",
            category="scanning",
            requirements=["aiohttp", "bs4"],
            config_schema={
                "payloads_file": str,
                "max_payloads": int,
                "timeout": int,
                "detect_waf": bool,
                "use_obfuscation": bool,
                "encoding_types": List[str],
                "waf_threshold": float,
                "max_retries": int,
                "delay_between_requests": float
            }
        )
    
    async def on_setup(self) -> None:
        """Initialize scanner resources."""
        # Validate configuration
        required = ["payloads_file", "timeout"]
        for option in required:
            if option not in self.config:
                raise ValueError(f"Missing required config: {option}")
                
        # Set defaults
        self.config.setdefault("max_payloads", 100)
        self.config.setdefault("detect_waf", True)
        self.config.setdefault("use_obfuscation", True)
        self.config.setdefault("encoding_types", ["html", "unicode"])
        self.config.setdefault("waf_threshold", 0.7)
        self.config.setdefault("max_retries", 3)
        self.config.setdefault("delay_between_requests", 0.1)
        
        # Initialize scan context
        self.scan_ctx = ScanContext()
        
        # Load payloads
        await self._load_payloads()
        
    async def _load_payloads(self) -> None:
        """Load XSS payloads from file."""
        try:
            self.scan_ctx.payloads = await self.load_file(self.config["payloads_file"])
            
            # Limit number of payloads if configured
            max_payloads = self.config["max_payloads"]
            if max_payloads > 0:
                self.scan_ctx.payloads = self.scan_ctx.payloads[:max_payloads]
                
            self.logger.info(f"Loaded {len(self.scan_ctx.payloads)} payloads")
            
        except Exception as e:
            raise RuntimeError(f"Failed to load payloads: {str(e)}")
            
    async def pre_scan(self) -> None:
        """Prepare for scanning."""
        self.logger.info(f"Starting scan of {self.context.target}")
        
        # Detect WAF if enabled
        if self.config["detect_waf"]:
            self.scan_ctx.waf_detected = await self._detect_waf()
            if self.scan_ctx.waf_detected:
                self.logger.warning(
                    f"WAF detected (score: {self.scan_ctx.waf_score:.2f}) - "
                    "using evasion techniques"
                )
                
        self.scan_ctx.successful_payloads = []
        
    async def _detect_waf(self) -> bool:
        """Detect if target is protected by WAF."""
        try:
            # Send probe requests with obvious XSS payloads
            probes = [
                "<script>alert(1)</script>",
                "';alert(1);//",
                '"><script>alert(1)</script>',
                '"><img src=x onerror=alert(1)>'
            ]
            
            for probe in probes:
                response = await self.make_request(
                    self.context.target,
                    params={"probe": probe},
                    verify_ssl=False  # Allow self-signed certs for testing
                )
                
                if not response:
                    continue
                    
                self.scan_ctx.total_requests += 1
                
                # Check response
                if await self._check_waf_response(response):
                    self.scan_ctx.blocked_requests += 1
                    
            # Calculate WAF score
            if self.scan_ctx.total_requests > 0:
                self.scan_ctx.waf_score = (
                    self.scan_ctx.blocked_requests / self.scan_ctx.total_requests
                )
                
            return self.scan_ctx.waf_score >= self.config["waf_threshold"]
            
        except Exception as e:
            self.logger.error(f"WAF detection failed: {str(e)}")
            return False
            
    async def _check_waf_response(self, response) -> bool:
        """Check if response indicates WAF blocking."""
        try:
            # WAF indicators
            waf_signs = {
                "headers": [
                    "WAF",
                    "Security",
                    "Firewall",
                    "Protection",
                    "OWASP",
                    "ModSecurity"
                ],
                "body": [
                    "blocked",
                    "forbidden",
                    "security",
                    "violation",
                    "attack",
                    "malicious"
                ],
                "status_codes": [403, 406, 429, 501]
            }
            
            # Check status code
            if response.status in waf_signs["status_codes"]:
                return True
                
            # Check headers
            headers = {k.lower(): v.lower() for k, v in response.headers.items()}
            for sign in waf_signs["headers"]:
                sign = sign.lower()
                if any(sign in v for v in headers.values()):
                    return True
                    
            # Check body
            content = await response.text()
            content = content.lower()
            for sign in waf_signs["body"]:
                if sign.lower() in content:
                    return True
                    
            return False
            
        except Exception as e:
            self.logger.error(f"WAF check failed: {str(e)}")
            return False
            
    async def do_scan(self) -> None:
        """Execute the scan."""
        for param_name, param_value in self.context.params.items():
            self.scan_ctx.current_parameter = param_name
            self.logger.info(f"Testing parameter: {param_name}")
            
            try:
                await self._test_parameter(param_name)
            except Exception as e:
                self.logger.error(f"Error testing parameter {param_name}: {str(e)}")
                self.add_error(f"Parameter test failed: {param_name}")
                continue
                
    async def _test_parameter(self, param: str) -> None:
        """Test a parameter with all payloads."""
        for payload in self.scan_ctx.payloads:
            # Apply obfuscation if enabled and WAF detected
            if self.config["use_obfuscation"] and self.scan_ctx.waf_detected:
                for encoding in self.config["encoding_types"]:
                    await self._test_payload(param, payload, encoding)
            else:
                await self._test_payload(param, payload)
                
            # Respect delay between requests
            if self.config["delay_between_requests"]:
                await asyncio.sleep(self.config["delay_between_requests"])
                
    async def _test_payload(self, param: str, payload: str,
                           encoding: str = None) -> None:
        """Test a single payload."""
        retries = self.config["max_retries"]
        while retries > 0:
            try:
                # Obfuscate payload if encoding specified
                if encoding:
                    from core.payload_obfuscator import PayloadObfuscator
                    obfuscator = PayloadObfuscator()
                    result = obfuscator.obfuscate(
                        payload=payload,
                        encoding_type=encoding
                    )
                    test_payload = result.payload
                else:
                    test_payload = payload
                    
                # Send request
                response = await self.make_request(
                    self.context.target,
                    params={param: test_payload},
                    verify_ssl=False
                )
                
                if not response:
                    retries -= 1
                    continue
                    
                # Analyze response
                content = await response.text()
                if await self._analyze_response(content, test_payload):
                    self.scan_ctx.successful_payloads.append(test_payload)
                    self.add_finding({
                        "type": "xss",
                        "parameter": param,
                        "payload": test_payload,
                        "original_payload": payload,
                        "encoding": encoding,
                        "evidence": self._extract_evidence(content, test_payload),
                        "context": self._detect_context(content, test_payload)
                    })
                    break
                    
                retries = 0  # Success, no need to retry
                
            except Exception as e:
                self.logger.error(f"Payload test failed: {str(e)}")
                retries -= 1
                if retries > 0:
                    await asyncio.sleep(1)  # Wait before retry
                    
    async def _analyze_response(self, content: str, payload: str) -> bool:
        """Analyze response for successful XSS."""
        try:
            # Parse HTML
            soup = BeautifulSoup(content, 'html.parser')
            
            # Check for exact payload reflection
            if payload in content:
                return True
                
            # Check for decoded payload
            if unescape(payload) in content:
                return True
                
            # Check for script execution context
            for script in soup.find_all('script'):
                if payload in script.string or unescape(payload) in script.string:
                    return True
                    
            # Check for event handler context
            for tag in soup.find_all(True):
                for attr in tag.attrs:
                    if attr.startswith('on') and payload in tag[attr]:
                        return True
                        
            # Check for URL context
            for tag in soup.find_all(['a', 'img', 'iframe', 'frame', 'embed', 'object']):
                for attr in ['href', 'src', 'data']:
                    if attr in tag.attrs and payload in tag[attr]:
                        return True
                        
            return False
            
        except Exception as e:
            self.logger.error(f"Response analysis failed: {str(e)}")
            return False
            
    def _detect_context(self, content: str, payload: str) -> str:
        """Detect the context where the payload was reflected."""
        try:
            soup = BeautifulSoup(content, 'html.parser')
            
            # Check script context
            for script in soup.find_all('script'):
                if payload in script.string:
                    return "javascript"
                    
            # Check event handler context
            for tag in soup.find_all(True):
                for attr in tag.attrs:
                    if attr.startswith('on') and payload in tag[attr]:
                        return "event_handler"
                        
            # Check URL context
            for tag in soup.find_all(['a', 'img', 'iframe', 'frame', 'embed', 'object']):
                for attr in ['href', 'src', 'data']:
                    if attr in tag.attrs and payload in tag[attr]:
                        return "url"
                        
            # Check attribute context
            for tag in soup.find_all(True):
                for attr, value in tag.attrs.items():
                    if isinstance(value, str) and payload in value:
                        return f"attribute:{attr}"
                        
            # Check text context
            text_nodes = soup.find_all(text=re.compile(re.escape(payload)))
            if text_nodes:
                return "text"
                
            return "unknown"
            
        except Exception:
            return "unknown"
            
    def _extract_evidence(self, content: str, payload: str,
                         context_lines: int = 2) -> str:
        """Extract evidence of XSS from response."""
        try:
            # Find payload position
            pos = content.find(payload)
            if pos == -1:
                return "Payload not found in response"
                
            # Get context around payload
            start = max(0, pos - 100)
            end = min(len(content), pos + len(payload) + 100)
            
            # Extract and format the evidence
            evidence = content[start:end]
            evidence = evidence.replace(payload, f"[PAYLOAD]{payload}[/PAYLOAD]")
            
            return evidence
            
        except Exception:
            return "Failed to extract evidence"
            
    async def post_scan(self) -> None:
        """Process scan results."""
        total_params = len(self.context.params)
        total_payloads = len(self.scan_ctx.payloads)
        successful = len(self.scan_ctx.successful_payloads)
        
        self.logger.info(
            f"Scan complete: {total_params} parameters, "
            f"{total_payloads} payloads, "
            f"{successful} successful injections"
        )
        
        if self.scan_ctx.waf_detected:
            self.logger.info(
                f"WAF Stats: Score={self.scan_ctx.waf_score:.2f}, "
                f"Blocked={self.scan_ctx.blocked_requests}/{self.scan_ctx.total_requests}"
            )
            
    async def on_cleanup(self) -> None:
        """Clean up resources."""
        self.scan_ctx = None 