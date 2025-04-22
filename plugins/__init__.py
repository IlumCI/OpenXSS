"""OpenXSS Plugin System

This package contains all the plugins for OpenXSS.
Plugins are automatically discovered and loaded from this directory.
"""

import os
import importlib
import inspect
from typing import Dict, Type
from pathlib import Path
from core.plugin_system import PluginInterface
from plugins.base_plugin import BasePlugin

# Registry of all available plugins
PLUGINS: Dict[str, Type[PluginInterface]] = {}

def discover_plugins() -> None:
    """Discover and register all plugins."""
    plugin_dir = Path(__file__).parent
    
    # Scan for plugin files
    for plugin_file in plugin_dir.glob("**/*.py"):
        if plugin_file.name.startswith("_") or plugin_file.name == "base_plugin.py":
            continue
            
        try:
            # Import module
            module_path = str(plugin_file.relative_to(plugin_dir.parent).with_suffix(""))
            module_name = module_path.replace(os.sep, ".")
            module = importlib.import_module(module_name)
            
            # Find plugin classes
            for name, obj in inspect.getmembers(module):
                if (inspect.isclass(obj) and 
                    issubclass(obj, BasePlugin) and 
                    obj != BasePlugin):
                    
                    # Create instance to get metadata
                    try:
                        plugin = obj()
                        plugin_name = plugin.metadata.name
                        PLUGINS[plugin_name] = obj
                    except Exception as e:
                        print(f"Error loading plugin {name}: {str(e)}")
                        
        except Exception as e:
            print(f"Error importing {plugin_file}: {str(e)}")
            
# Auto-discover plugins on import
discover_plugins()
