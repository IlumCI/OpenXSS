#!/usr/bin/env python3
"""Plugin template generator for OpenXSS."""

import os
import sys
import argparse
from pathlib import Path

PLUGIN_TEMPLATE = '''"""
{description}
"""

from typing import Dict, Any
from plugins.base_plugin import BasePlugin, PluginMetadata

class {class_name}(BasePlugin):
    """Plugin for {plugin_name}."""
    
    @property
    def metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name="{plugin_name}",
            version="1.0.0",
            author="{author}",
            description="{description}",
            category="{category}",
            requirements=[],  # Add required packages here
            config_schema={{
                # Add configuration options here
                "option1": str,
                "option2": int
            }}
        )
    
    async def on_setup(self) -> None:
        """Initialize plugin resources."""
        # Add setup code here
        pass
        
    async def pre_scan(self) -> None:
        """Run before scanning starts."""
        self.logger.info("Starting {plugin_name} scan...")
        
    async def do_scan(self) -> None:
        """Main scanning logic."""
        target = self.context.target
        params = self.context.params
        config = self.config
        
        # Add scanning logic here
        # Use self.make_request() for HTTP requests
        # Use self.add_finding() to report findings
        # Use self.add_error() to report errors
        pass
        
    async def post_scan(self) -> None:
        """Run after scanning completes."""
        self.logger.info("Completed {plugin_name} scan")
        
    async def on_cleanup(self) -> None:
        """Clean up resources."""
        # Add cleanup code here
        pass
'''

CONFIG_TEMPLATE = '''
# Configuration for {plugin_name}
{plugin_name}:
  # Add your plugin's configuration options here
  option1: default_value
  option2: 123
'''

def create_plugin(args):
    """Create a new plugin from template."""
    # Convert plugin name to class name
    class_name = ''.join(word.capitalize() for word in args.name.split('_'))
    
    # Create plugin file
    plugin_path = Path('plugins') / f"{args.name}.py"
    if plugin_path.exists() and not args.force:
        print(f"Error: Plugin {args.name} already exists. Use --force to overwrite.")
        return False
        
    # Create plugin file
    plugin_content = PLUGIN_TEMPLATE.format(
        plugin_name=args.name,
        class_name=class_name,
        author=args.author,
        description=args.description,
        category=args.category
    )
    
    with open(plugin_path, 'w') as f:
        f.write(plugin_content)
        
    print(f"Created plugin: {plugin_path}")
    
    # Add configuration template
    config_path = Path('config.yaml')
    if config_path.exists():
        with open(config_path, 'a') as f:
            f.write(CONFIG_TEMPLATE.format(plugin_name=args.name))
        print(f"Added configuration template to: {config_path}")
        
    return True

def main():
    parser = argparse.ArgumentParser(description="Create a new OpenXSS plugin")
    
    parser.add_argument(
        "name",
        help="Plugin name (snake_case)"
    )
    
    parser.add_argument(
        "-a", "--author",
        help="Plugin author name",
        default="Anonymous"
    )
    
    parser.add_argument(
        "-d", "--description",
        help="Plugin description",
        default="A new OpenXSS plugin"
    )
    
    parser.add_argument(
        "-c", "--category",
        help="Plugin category",
        choices=["scanning", "discovery", "utility"],
        default="scanning"
    )
    
    parser.add_argument(
        "-f", "--force",
        help="Overwrite existing plugin",
        action="store_true"
    )
    
    args = parser.parse_args()
    
    if create_plugin(args):
        print(f"""
Plugin created successfully!

To use your plugin:
1. Edit plugins/{args.name}.py to implement your scanning logic
2. Configure your plugin in config.yaml
3. Run it with: python openxss.py -t <target> --plugin {args.name}

Need help? Check the plugin development guide in the docs!
""")
    
if __name__ == "__main__":
    main() 