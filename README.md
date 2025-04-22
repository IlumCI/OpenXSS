# OpenXSS

A modern, modular, and superior XSS scanner with advanced features and plugin support.

## Features

- 🔌 Plugin-based Architecture
- 🎯 Smart Payload Engine
- 🧠 Context-aware Fuzzing
- 🛡️ WAF Detection & Bypass
- 🔄 Payload Obfuscation
- 🚀 Async Operations
- 📊 Rich Terminal Output

## Installation

1. Clone the repository:
```bash
git clone https://github.com/IlumCI/OpenXSS.git
cd OpenXSS
```

2. Create a virtual environment (recommended):
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

4. Run setup:
```bash
python openxss.py --setup
```

## Usage

Basic scan:
```bash
python openxss.py -t https://example.com
```

Test specific parameters:
```bash
python openxss.py -t https://example.com -p param1=test param2=test
```

Run specific plugin:
```bash
python openxss.py -t https://example.com --plugin param_bruteforcer
```

Use custom configuration:
```bash
python openxss.py -t https://example.com -c custom_config.yaml
```

## Configuration

Create a `config.yaml` file to configure plugins:

```yaml
param_bruteforcer:
  wordlist: data/params.txt
  concurrent_requests: 10
  timeout: 10
  test_payload: "<script>alert(1)</script>"

wordlist_scanner:
  wordlist: data/xss_payloads.txt
  concurrent_requests: 10
  timeout: 10
  use_obfuscation: true
  encoding_types:
    - html
    - unicode
```

## Plugins

### Built-in Plugins

1. **Parameter Bruteforcer**
   - Discovers injectable parameters through brute force
   - Supports concurrent testing
   - Smart parameter detection

2. **Wordlist Scanner**
   - Tests XSS payloads from wordlist
   - Supports payload obfuscation
   - Multiple encoding types
   - Context-aware testing

### Creating Custom Plugins

Create a new plugin by implementing the `PluginInterface`:

```python
from core.plugin_system import PluginInterface, PluginMetadata, PluginResult

class CustomPlugin(PluginInterface):
    @property
    def metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name="custom_plugin",
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
    
    async def setup(self, config: Dict[str, Any]) -> bool:
        # Setup code
        return True
    
    async def scan(self, target: str, params: Dict[str, Any]) -> PluginResult:
        # Scanning code
        return PluginResult(...)
    
    async def cleanup(self) -> None:
        # Cleanup code
        pass
```

## Contributing

1. Fork the repository
2. Create your feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## License

This project is licensed under the GNU General Public License v3.0 - see the LICENSE file for details.
