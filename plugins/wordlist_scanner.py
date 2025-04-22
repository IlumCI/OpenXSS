from typing import Dict, List, Any
import aiohttp
import asyncio
import time
from core.plugin_system import PluginInterface, PluginMetadata, PluginResult
from core.payload_obfuscator import PayloadObfuscator

class WordlistScanner(PluginInterface):
    """Plugin for testing XSS payloads from a wordlist."""
    
    @property
    def metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name="wordlist_scanner",
            version="1.0.0",
            author="OpenXSS",
            description="Tests XSS payloads from a wordlist against target parameters",
            category="scanning",
            requirements=["aiohttp"],
            config_schema={
                "wordlist": str,
                "concurrent_requests": int,
                "timeout": int,
                "use_obfuscation": bool,
                "encoding_types": List[str]
            }
        )
    
    async def setup(self, config: Dict[str, Any]) -> bool:
        """Set up the plugin with configuration."""
        self.wordlist_path = config.get("wordlist", "data/xss_payloads.txt")
        self.concurrent_requests = config.get("concurrent_requests", 10)
        self.timeout = config.get("timeout", 10)
        self.use_obfuscation = config.get("use_obfuscation", False)
        self.encoding_types = config.get("encoding_types", ["html", "unicode"])
        
        if self.use_obfuscation:
            self.obfuscator = PayloadObfuscator()
        
        try:
            # Load payload wordlist
            with open(self.wordlist_path) as f:
                self.payloads = [line.strip() for line in f if line.strip()]
            return True
        except Exception as e:
            print(f"Error loading wordlist: {str(e)}")
            return False
    
    async def scan(self, target: str, params: Dict[str, Any]) -> PluginResult:
        """Execute the wordlist-based scan."""
        start_time = time.time()
        findings = []
        errors = []
        
        # Process each parameter
        for param_name, param_value in params.items():
            param_findings = await self._scan_parameter(target, param_name)
            findings.extend(param_findings)
            
        execution_time = time.time() - start_time
        
        return PluginResult(
            plugin_name=self.metadata.name,
            success=len(findings) > 0,
            findings=findings,
            execution_time=execution_time,
            errors=errors if errors else None
        )
    
    async def _scan_parameter(self, target: str, param: str) -> List[Dict]:
        """Scan a single parameter with all payloads."""
        findings = []
        
        async with aiohttp.ClientSession() as session:
            tasks = []
            for i in range(0, len(self.payloads), self.concurrent_requests):
                batch = self.payloads[i:i + self.concurrent_requests]
                
                # Process payloads with obfuscation if enabled
                test_payloads = []
                for payload in batch:
                    if self.use_obfuscation:
                        for encoding in self.encoding_types:
                            obfuscated = self.obfuscator.obfuscate(
                                payload=payload,
                                encoding_type=encoding,
                                split_payload=False
                            )
                            test_payloads.append((payload, obfuscated.payload))
                    else:
                        test_payloads.append((payload, payload))
                
                # Create tasks for testing
                tasks.extend([
                    self._test_payload(session, target, param, original, test)
                    for original, test in test_payloads
                ])
                
                # Run batch of tasks
                batch_results = await asyncio.gather(*tasks, return_exceptions=True)
                
                # Process results
                for (original, test), result in zip(test_payloads, batch_results):
                    if isinstance(result, Exception):
                        continue
                    elif result:
                        findings.append({
                            "parameter": param,
                            "original_payload": original,
                            "tested_payload": test,
                            "reflection_type": result
                        })
                
                tasks = []
        
        return findings
    
    async def _test_payload(self, session: aiohttp.ClientSession,
                          target: str, param: str,
                          original: str, payload: str) -> str:
        """Test a single payload against a parameter."""
        try:
            async with session.get(
                target,
                params={param: payload},
                timeout=self.timeout
            ) as response:
                if response.status != 200:
                    return None
                    
                content = await response.text()
                
                # Check for successful injection
                if payload in content:
                    if "<script>" in content and "</script>" in content:
                        return "html_script"
                    elif "alert" in content or "prompt" in content:
                        return "javascript_context"
                    else:
                        return "raw_reflection"
                        
                return None
                
        except asyncio.TimeoutError:
            raise Exception(f"Timeout testing payload: {payload}")
        except Exception as e:
            raise Exception(f"Error testing payload: {str(e)}")
    
    async def cleanup(self) -> None:
        """Clean up resources."""
        pass 