# OpenXSS Plugin Development Guide

## Table of Contents
1. [Introduction](#introduction)
2. [Getting Started](#getting-started)
3. [Plugin Structure](#plugin-structure)
4. [Plugin Lifecycle](#plugin-lifecycle)
5. [Plugin Context](#plugin-context)
6. [Utility Methods](#utility-methods)
7. [Best Practices](#best-practices)
8. [Examples](#examples)
9. [Testing](#testing)
10. [Troubleshooting](#troubleshooting)

## Introduction

OpenXSS plugins are modular components that extend the scanner's functionality. Each plugin is a Python class that inherits from `BasePlugin` and implements specific scanning logic.

### Plugin Categories
- **Scanning**: Core XSS detection plugins
- **Discovery**: Parameter and endpoint discovery plugins
- **Utility**: Helper plugins for tasks like WAF detection

## Getting Started

### Creating a New Plugin

Use the plugin generator:
```bash
python tools/create_plugin.py my_plugin -a "Your Name" -d "Plugin description" -c scanning
```

This creates:
- `plugins/my_plugin.py`: Plugin implementation
- Configuration entry in `config.yaml`

### Basic Plugin Structure
```python
from plugins.base_plugin import BasePlugin, PluginMetadata

class MyPlugin(BasePlugin):
    @property
    def metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name="my_plugin",
            version="1.0.0",
            author="Your Name",
            description="Plugin description",
            category="scanning",
            requirements=["package1", "package2"],
            config_schema={
                "option1": str,
                "option2": int
            }
        )

    async def do_scan(self) -> None:
        # Your scanning logic here
        pass
```

## Plugin Structure

### Metadata
The `metadata` property defines your plugin's characteristics:
```python
@property
def metadata(self) -> PluginMetadata:
    return PluginMetadata(
        name="my_plugin",          # Unique identifier
        version="1.0.0",          # Semantic versioning
        author="Your Name",       # Author information
        description="...",        # Plugin description
        category="scanning",      # Plugin category
        requirements=[],          # Required packages
        config_schema={           # Configuration schema
            "option1": str,
            "option2": int
        }
    )
```

### Configuration
Define your plugin's configuration in `config.yaml`:
```yaml
my_plugin:
  option1: "value"
  option2: 123
  timeout: 30
  max_retries: 3
```

Access configuration in your plugin:
```python
async def do_scan(self) -> None:
    option1 = self.config["option1"]
    timeout = self.config.get("timeout", 30)  # With default
```

## Plugin Lifecycle

Plugins follow a defined lifecycle with hooks for each stage:

1. **Setup** (`on_setup`):
   ```python
   async def on_setup(self) -> None:
       """Initialize resources."""
       self.my_resource = await self.initialize_resource()
   ```

2. **Pre-scan** (`pre_scan`):
   ```python
   async def pre_scan(self) -> None:
       """Run before scanning starts."""
       self.logger.info("Starting scan...")
       await self.prepare_environment()
   ```

3. **Scan** (`do_scan`):
   ```python
   async def do_scan(self) -> None:
       """Main scanning logic."""
       response = await self.make_request(self.context.target)
       if self.is_vulnerable(response):
           self.add_finding({
               "type": "xss",
               "payload": "<script>alert(1)</script>",
               "location": "parameter"
           })
   ```

4. **Post-scan** (`post_scan`):
   ```python
   async def post_scan(self) -> None:
       """Run after scanning completes."""
       await self.analyze_results()
   ```

5. **Cleanup** (`on_cleanup`):
   ```python
   async def on_cleanup(self) -> None:
       """Clean up resources."""
       await self.my_resource.close()
   ```

## Plugin Context

The `PluginContext` object provides access to:
- Target URL
- Parameters
- Configuration
- HTTP session
- Logger
- Findings and errors lists

```python
async def do_scan(self) -> None:
    target = self.context.target
    params = self.context.params
    session = self.context.session
    logger = self.context.logger
```

## Utility Methods

### HTTP Requests
```python
# Basic GET request
response = await self.make_request(url)

# POST request with parameters
response = await self.make_request(
    url,
    method="POST",
    params={"id": "123"},
    data={"payload": "<script>alert(1)</script>"}
)

# Request with delay
response = await self.make_request(url, delay=0.5)
```

### Findings and Errors
```python
# Add a finding
self.add_finding({
    "type": "xss",
    "payload": payload,
    "parameter": param_name,
    "evidence": evidence
})

# Add an error
self.add_error(f"Failed to test parameter: {param_name}")
```

## Best Practices

1. **Error Handling**
```python
async def do_scan(self) -> None:
    try:
        response = await self.make_request(self.context.target)
        # Process response
    except Exception as e:
        self.add_error(f"Scan failed: {str(e)}")
```

2. **Resource Management**
```python
async def on_setup(self) -> None:
    self.resources = []
    
async def on_cleanup(self) -> None:
    for resource in self.resources:
        await resource.close()
```

3. **Logging**
```python
def process_response(self, response):
    self.logger.debug(f"Processing response: {response.status}")
    self.logger.info("Found potential XSS")
    self.logger.warning("Rate limit detected")
    self.logger.error("Request failed")
```

4. **Configuration Validation**
```python
async def on_setup(self) -> None:
    required = ["option1", "option2"]
    for option in required:
        if option not in self.config:
            raise ValueError(f"Missing required config: {option}")
```

## Examples

### Basic Scanner Plugin
```python
class BasicScanner(BasePlugin):
    @property
    def metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name="basic_scanner",
            version="1.0.0",
            author="Your Name",
            description="Basic XSS scanner",
            category="scanning",
            requirements=[],
            config_schema={
                "payloads": List[str],
                "timeout": int
            }
        )
    
    async def do_scan(self) -> None:
        payloads = self.config["payloads"]
        for param, value in self.context.params.items():
            for payload in payloads:
                response = await self.make_request(
                    self.context.target,
                    params={param: payload}
                )
                if response and payload in await response.text():
                    self.add_finding({
                        "type": "reflection",
                        "parameter": param,
                        "payload": payload
                    })
```

### Advanced Scanner Plugin
```python
class AdvancedScanner(BasePlugin):
    async def on_setup(self) -> None:
        # Load payloads database
        self.payloads = await self.load_payloads()
        # Initialize detection engine
        self.detector = XSSDetector()
    
    async def pre_scan(self) -> None:
        # Detect WAF
        self.waf_detected = await self.detect_waf()
        if self.waf_detected:
            self.logger.info("WAF detected, using evasion techniques")
    
    async def do_scan(self) -> None:
        for param, value in self.context.params.items():
            await self.test_parameter(param)
    
    async def test_parameter(self, param: str) -> None:
        for payload in self.payloads:
            if self.waf_detected:
                payload = await self.obfuscate_payload(payload)
            
            response = await self.make_request(
                self.context.target,
                params={param: payload}
            )
            
            if response:
                finding = await self.detector.analyze(
                    response,
                    payload,
                    param
                )
                if finding:
                    self.add_finding(finding)
```

## Testing

### Using the Test Framework
```bash
python tools/test_plugin.py my_plugin -t http://example.com
```

### Writing Plugin Tests
```python
# test_my_plugin.py
async def test_plugin():
    plugin = MyPlugin()
    await plugin.setup({"option1": "value"})
    
    result = await plugin.scan(
        target="http://example.com",
        params={"test": "value"}
    )
    
    assert result.success
    assert len(result.findings) > 0
```

## Troubleshooting

### Common Issues

1. **Plugin Not Loading**
   - Check plugin file name matches class name (snake_case)
   - Verify plugin inherits from BasePlugin
   - Check for syntax errors

2. **Configuration Errors**
   - Verify config schema matches config.yaml
   - Check required options are provided
   - Validate option types

3. **Runtime Errors**
   - Use proper error handling
   - Check HTTP request parameters
   - Verify resource cleanup

### Debug Mode
```python
async def do_scan(self) -> None:
    self.logger.setLevel(logging.DEBUG)
    self.logger.debug("Detailed debugging information")
```

### Getting Help
- Check the OpenXSS documentation
- Review existing plugins for examples
- Open an issue on GitHub
- Join the community Discord 