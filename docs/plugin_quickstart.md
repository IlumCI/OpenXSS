# OpenXSS Plugin Quick Reference

## Quick Start

1. Create plugin:
```bash
python tools/create_plugin.py my_plugin
```

2. Implement scanning logic:
```python
async def do_scan(self) -> None:
    response = await self.make_request(self.context.target)
    if self.is_vulnerable(response):
        self.add_finding({"type": "xss"})
```

3. Test plugin:
```bash
python tools/test_plugin.py my_plugin
```

## Common Patterns

### HTTP Requests
```python
# GET request
response = await self.make_request(url)

# POST request
response = await self.make_request(url, method="POST", data=data)

# With parameters
response = await self.make_request(url, params={"id": "123"})

# With delay
response = await self.make_request(url, delay=0.5)
```

### Findings
```python
# Add finding
self.add_finding({
    "type": "xss",
    "payload": payload,
    "parameter": param
})

# Add error
self.add_error("Request failed")
```

### Configuration
```python
# Define schema
config_schema = {
    "timeout": int,
    "payloads": List[str]
}

# Access config
timeout = self.config["timeout"]
payloads = self.config.get("payloads", [])
```

### Logging
```python
self.logger.debug("Debug message")
self.logger.info("Info message")
self.logger.warning("Warning message")
self.logger.error("Error message")
```

## Plugin Hooks

```python
async def on_setup(self) -> None:
    """Initialize resources"""
    pass

async def pre_scan(self) -> None:
    """Before scanning"""
    pass

async def do_scan(self) -> None:
    """Main scanning logic"""
    pass

async def post_scan(self) -> None:
    """After scanning"""
    pass

async def on_cleanup(self) -> None:
    """Cleanup resources"""
    pass
```

## Plugin Context

```python
self.context.target      # Target URL
self.context.params      # Request parameters
self.context.config      # Plugin configuration
self.context.session     # HTTP session
self.context.logger      # Plugin logger
self.context.findings    # Findings list
self.context.errors     # Errors list
```

## Best Practices

1. Always use async/await
2. Handle errors properly
3. Clean up resources
4. Use type hints
5. Document your code
6. Follow naming conventions

## Common Issues

1. Plugin not loading:
   - Check file name matches class name
   - Verify imports
   - Check syntax

2. Configuration errors:
   - Validate config schema
   - Check required options
   - Verify types

3. Runtime errors:
   - Use try/except
   - Check parameters
   - Verify cleanup

## Testing Tips

1. Use the test framework
2. Test edge cases
3. Verify findings
4. Check resource cleanup
5. Test with different configs

## Need Help?

- Read full documentation: `docs/plugin_development.md`
- Check example plugins: `plugins/examples/`
- Run tests: `python tools/test_plugin.py`
- Debug mode: Set log level to DEBUG 