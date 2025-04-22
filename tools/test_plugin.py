#!/usr/bin/env python3
"""Test framework for OpenXSS plugins."""

import os
import sys
import asyncio
import argparse
import yaml
from pathlib import Path
from typing import Dict, Any, Type

# Add parent directory to path for imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.plugin_system import PluginInterface
from plugins.base_plugin import BasePlugin

class PluginTester:
    """Framework for testing OpenXSS plugins."""
    
    def __init__(self, plugin_name: str, config_file: str = "config.yaml"):
        self.plugin_name = plugin_name
        self.config_file = config_file
        
    def _load_plugin(self) -> Type[PluginInterface]:
        """Load plugin class."""
        try:
            # Import plugin module
            module_name = f"plugins.{self.plugin_name}"
            plugin_module = __import__(module_name, fromlist=[''])
            
            # Find plugin class
            for attr_name in dir(plugin_module):
                attr = getattr(plugin_module, attr_name)
                if (isinstance(attr, type) and
                    issubclass(attr, BasePlugin) and
                    attr != BasePlugin):
                    return attr
                    
            raise ValueError(f"No plugin class found in {module_name}")
            
        except Exception as e:
            print(f"Error loading plugin: {str(e)}")
            sys.exit(1)
            
    def _load_config(self) -> Dict[str, Any]:
        """Load plugin configuration."""
        try:
            with open(self.config_file) as f:
                config = yaml.safe_load(f)
                return config.get(self.plugin_name, {})
        except Exception as e:
            print(f"Error loading config: {str(e)}")
            return {}
            
    async def run_tests(self, target: str):
        """Run plugin tests."""
        # Load plugin and config
        plugin_class = self._load_plugin()
        config = self._load_config()
        
        print(f"\nTesting plugin: {self.plugin_name}")
        print("=" * 50)
        
        # Create plugin instance
        plugin = plugin_class()
        
        try:
            # Test setup
            print("\nTesting setup...")
            setup_ok = await plugin.setup(config)
            if not setup_ok:
                print("❌ Setup failed!")
                return
            print("✅ Setup successful")
            
            # Test scanning
            print("\nTesting scan...")
            result = await plugin.scan(
                target=target,
                params={"test": "value"}
            )
            
            # Print results
            print("\nScan Results:")
            print(f"Success: {'✅' if result.success else '❌'}")
            print(f"Execution time: {result.execution_time:.2f}s")
            print(f"Findings: {len(result.findings)}")
            
            if result.findings:
                print("\nFindings:")
                for i, finding in enumerate(result.findings, 1):
                    print(f"\n{i}. {finding.get('type', 'Unknown')}:")
                    for k, v in finding.items():
                        if k != 'type':
                            print(f"   {k}: {v}")
                            
            if result.errors:
                print("\nErrors:")
                for error in result.errors:
                    print(f"❌ {error}")
                    
            # Test cleanup
            print("\nTesting cleanup...")
            await plugin.cleanup()
            print("✅ Cleanup successful")
            
        except Exception as e:
            print(f"\n❌ Test failed: {str(e)}")
            
def main():
    parser = argparse.ArgumentParser(description="Test OpenXSS plugins")
    
    parser.add_argument(
        "plugin",
        help="Name of the plugin to test"
    )
    
    parser.add_argument(
        "-t", "--target",
        help="Target URL for testing",
        default="http://example.com"
    )
    
    parser.add_argument(
        "-c", "--config",
        help="Path to config file",
        default="config.yaml"
    )
    
    args = parser.parse_args()
    
    # Run tests
    tester = PluginTester(args.plugin, args.config)
    asyncio.run(tester.run_tests(args.target))
    
if __name__ == "__main__":
    main() 