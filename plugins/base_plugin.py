"""Base plugin template for OpenXSS plugins."""

from abc import ABC
from typing import Dict, Any, Optional, List, Union
import aiohttp
import asyncio
import logging
from dataclasses import dataclass, field
from datetime import datetime
import json
from pathlib import Path

from core.plugin_system import PluginInterface, PluginMetadata, PluginResult

@dataclass
class PluginContext:
    """Context object passed to plugin hooks."""
    target: str
    params: Dict[str, Any]
    config: Dict[str, Any]
    session: aiohttp.ClientSession
    logger: logging.Logger
    start_time: datetime = field(default_factory=datetime.now)
    findings: List[Dict[str, Any]] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    _resources: List[Any] = field(default_factory=list)

    def add_resource(self, resource: Any) -> None:
        """Add a resource to be cleaned up."""
        self._resources.append(resource)

    async def cleanup_resources(self) -> None:
        """Clean up all resources."""
        for resource in self._resources:
            try:
                if hasattr(resource, 'close'):
                    if asyncio.iscoroutinefunction(resource.close):
                        await resource.close()
                    else:
                        resource.close()
                elif hasattr(resource, '__aenter__'):
                    await resource.__aexit__(None, None, None)
            except Exception as e:
                logging.error(f"Error cleaning up resource: {str(e)}")

class BasePlugin(PluginInterface, ABC):
    """Base class for OpenXSS plugins providing common functionality."""
    
    def __init__(self):
        self.logger = logging.getLogger(self.__class__.__name__)
        self.context: Optional[PluginContext] = None
        self.config: Dict[str, Any] = {}
        
    async def _create_session(self, headers: Dict[str, str] = None,
                            timeout: int = None) -> aiohttp.ClientSession:
        """Create an HTTP session with default settings."""
        if timeout is None:
            timeout = self.config.get("timeout", 30)
            
        return aiohttp.ClientSession(
            headers=headers or {},
            timeout=aiohttp.ClientTimeout(total=timeout),
            raise_for_status=False  # Don't raise for non-200 responses
        )
        
    async def setup(self, config: Dict[str, Any]) -> bool:
        """Set up plugin with configuration."""
        try:
            # Store config for later use
            self.config = config
            
            # Validate config schema
            if not self._validate_config():
                return False
            
            # Initialize any plugin-specific resources
            await self.on_setup()
            
            return True
        except Exception as e:
            self.logger.error(f"Setup failed: {str(e)}")
            return False
            
    def _validate_config(self) -> bool:
        """Validate configuration against schema."""
        try:
            schema = self.metadata.config_schema
            for key, value_type in schema.items():
                if key in self.config:
                    value = self.config[key]
                    if value_type == List[str] and isinstance(value, list):
                        if not all(isinstance(x, str) for x in value):
                            self.logger.error(f"Invalid type for {key}: all elements must be strings")
                            return False
                    elif not isinstance(value, value_type):
                        self.logger.error(
                            f"Invalid type for {key}: expected {value_type}, got {type(value)}"
                        )
                        return False
            return True
        except Exception as e:
            self.logger.error(f"Config validation failed: {str(e)}")
            return False
            
    async def scan(self, target: str, params: Dict[str, Any],
                   headers: Dict[str, str] = None,
                   delay: float = 0) -> PluginResult:
        """Execute the plugin's scanning functionality."""
        try:
            # Create HTTP session
            async with await self._create_session(headers) as session:
                # Create context
                self.context = PluginContext(
                    target=target,
                    params=params,
                    config=self.config,
                    session=session,
                    logger=self.logger
                )
                
                try:
                    # Run pre-scan hook
                    await self.pre_scan()
                    
                    # Run main scan
                    await self.do_scan()
                    
                    # Run post-scan hook
                    await self.post_scan()
                    
                finally:
                    # Always clean up context resources
                    if self.context:
                        await self.context.cleanup_resources()
                
                # Calculate execution time
                execution_time = (datetime.now() - self.context.start_time).total_seconds()
                
                # Create result
                return PluginResult(
                    plugin_name=self.metadata.name,
                    success=len(self.context.findings) > 0,
                    findings=self.context.findings,
                    execution_time=execution_time,
                    errors=self.context.errors if self.context.errors else None
                )
                
        except Exception as e:
            self.logger.error(f"Scan failed: {str(e)}")
            return PluginResult(
                plugin_name=self.metadata.name,
                success=False,
                findings=[],
                execution_time=0,
                errors=[str(e)]
            )
        finally:
            # Clean up plugin resources
            await self.cleanup()
            
    async def cleanup(self) -> None:
        """Clean up plugin resources."""
        try:
            await self.on_cleanup()
        except Exception as e:
            self.logger.error(f"Cleanup failed: {str(e)}")
        finally:
            self.context = None
            
    # Plugin lifecycle hooks
    
    async def on_setup(self) -> None:
        """Hook called during plugin setup."""
        pass
        
    async def pre_scan(self) -> None:
        """Hook called before scanning starts."""
        pass
        
    async def do_scan(self) -> None:
        """Main scanning logic. Must be implemented by plugins."""
        raise NotImplementedError("Plugins must implement do_scan()")
        
    async def post_scan(self) -> None:
        """Hook called after scanning completes."""
        pass
        
    async def on_cleanup(self) -> None:
        """Hook called during cleanup."""
        pass
        
    # Utility methods for plugins
    
    async def make_request(
        self,
        url: str,
        method: str = "GET",
        params: Dict[str, Any] = None,
        data: Union[Dict[str, Any], str] = None,
        json_data: Dict[str, Any] = None,
        headers: Dict[str, str] = None,
        delay: float = 0,
        timeout: int = None,
        verify_ssl: bool = True
    ) -> Optional[aiohttp.ClientResponse]:
        """Make an HTTP request with error handling and delay."""
        if not self.context or not self.context.session:
            raise RuntimeError("No active session - plugin not properly initialized")
            
        if delay:
            await asyncio.sleep(delay)
            
        try:
            # Merge headers
            request_headers = dict(self.context.session._default_headers)
            if headers:
                request_headers.update(headers)
                
            # Handle data
            if isinstance(data, dict):
                data = json.dumps(data)
                request_headers['Content-Type'] = 'application/json'
                
            return await self.context.session.request(
                method,
                url,
                params=params,
                data=data,
                json=json_data,
                headers=request_headers,
                timeout=timeout,
                ssl=verify_ssl
            )
        except asyncio.TimeoutError:
            self.add_error(f"Request timeout: {url}")
            return None
        except Exception as e:
            self.add_error(f"Request failed: {str(e)}")
            return None
            
    def add_finding(self, finding: Dict[str, Any]) -> None:
        """Add a finding to the results."""
        if self.context:
            # Add metadata
            finding.update({
                "timestamp": datetime.now().isoformat(),
                "plugin": self.metadata.name,
                "target": self.context.target
            })
            self.context.findings.append(finding)
            self.logger.info(f"Found vulnerability: {finding['type']}")
            
    def add_error(self, error: str) -> None:
        """Add an error message."""
        if self.context:
            self.context.errors.append(error)
            self.logger.error(error)
            
    async def load_file(self, path: Union[str, Path]) -> List[str]:
        """Load lines from a file."""
        path = Path(path)
        if not path.exists():
            raise FileNotFoundError(f"File not found: {path}")
            
        with open(path) as f:
            return [line.strip() for line in f if line.strip()] 