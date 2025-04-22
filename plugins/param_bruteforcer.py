from typing import Dict, List, Any
import aiohttp
import asyncio
import time
from core.plugin_system import PluginInterface, PluginMetadata, PluginResult

class ParamBruteforcer(PluginInterface):
    """Plugin for discovering injectable parameters through brute force."""
    
    @property
    def metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name="param_bruteforcer",
            version="1.0.0",
            author="OpenXSS",
            description="Discovers potentially injectable parameters through brute force",
            category="discovery",
            requirements=["aiohttp"],
            config_schema={
                "wordlist": str,
                "concurrent_requests": int,
                "timeout": int,
                "test_payload": str
            }
        )
    
    async def setup(self, config: Dict[str, Any]) -> bool:
        """Set up the plugin with configuration."""
        self.wordlist_path = config.get("wordlist", "data/params.txt")
        self.concurrent_requests = config.get("concurrent_requests", 10)
        self.timeout = config.get("timeout", 10)
        self.test_payload = config.get("test_payload", "<script>alert(1)</script>")
        
        try:
            # Load parameter wordlist
            with open(self.wordlist_path) as f:
                self.params = [line.strip() for line in f if line.strip()]
            return True
        except Exception as e:
            print(f"Error loading wordlist: {str(e)}")
            return False
    
    async def scan(self, target: str, params: Dict[str, Any]) -> PluginResult:
        """Execute the parameter brute force scan."""
        start_time = time.time()
        findings = []
        errors = []
        
        async with aiohttp.ClientSession() as session:
            # Create task groups for concurrent scanning
            tasks = []
            for i in range(0, len(self.params), self.concurrent_requests):
                batch = self.params[i:i + self.concurrent_requests]
                tasks.extend([
                    self._test_parameter(session, target, param)
                    for param in batch
                ])
                
                # Run batch of tasks
                batch_results = await asyncio.gather(*tasks, return_exceptions=True)
                
                # Process results
                for param, result in zip(batch, batch_results):
                    if isinstance(result, Exception):
                        errors.append(f"Error testing {param}: {str(result)}")
                    elif result:
                        findings.append({
                            "parameter": param,
                            "reflection_type": result
                        })
                
                tasks = []
        
        execution_time = time.time() - start_time
        
        return PluginResult(
            plugin_name=self.metadata.name,
            success=len(findings) > 0,
            findings=findings,
            execution_time=execution_time,
            errors=errors if errors else None
        )
    
    async def _test_parameter(self, session: aiohttp.ClientSession,
                            target: str, param: str) -> str:
        """Test a single parameter for injection possibilities."""
        try:
            # Test parameter with payload
            async with session.get(
                target,
                params={param: self.test_payload},
                timeout=self.timeout
            ) as response:
                if response.status != 200:
                    return None
                    
                content = await response.text()
                
                # Check for different types of reflections
                if self.test_payload in content:
                    if "<script>" in content and "</script>" in content:
                        return "html_script"
                    elif "alert(1)" in content:
                        return "javascript_context"
                    else:
                        return "raw_reflection"
                        
                return None
                
        except asyncio.TimeoutError:
            raise Exception(f"Timeout testing parameter {param}")
        except Exception as e:
            raise Exception(f"Error testing parameter {param}: {str(e)}")
    
    async def cleanup(self) -> None:
        """Clean up resources."""
        pass 