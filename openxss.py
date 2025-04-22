#!/usr/bin/env python3
import argparse
import asyncio
import logging
import os
import sys
from pathlib import Path
from typing import Dict, Any, List
import json
from rich.console import Console
from rich import print as rprint
from rich.table import Table
from rich.markdown import Markdown
from rich.panel import Panel
from rich.prompt import Prompt, Confirm
from rich.live import Live

from core.plugin_system import PluginManager
from core.payload_obfuscator import PayloadObfuscator

VERSION = "3.1.5"
BANNER = '''[red]
                                                                                          
       :                                                                                  
      t#,                          ,;  L.                                    .           .
     ;##W.     t                 f#i   EW:        ,ft                       ;W          ;W
    :#L:WE     ED.             .E#t    E##;       t#E                      f#E         f#E
   .KG  ,#D    E#K:           i#W,     E###t      t#E  :KW,      L       .E#f        .E#f 
   EE    ;#f   E##W;         L#D.      E#fE#f     t#E   ,#W:   ,KG      iWW;        iWW;  
  f#.     t#i  E#E##t      :K#Wfff;    E#t D#G    t#E    ;#W. jWi      L##Lffi     L##Lffi
  :#G     GK   E#ti##f     i##WLLLLt   E#t  f#E.  t#E     i#KED.      tLLG##L     tLLG##L 
   ;#L   LW.   E#t ;##D.    .E#L       E#t   t#K: t#E      L#W.         ,W#i        ,W#i  
    t#f f#:    E#ELLE##K:     f#E:     E#t    ;#W,t#E    .GKj#K.       j#E.        j#E.   
     f#D#;     E#L;;;;;;,      ,WW;    E#t     :K#D#E   iWf  i#K.    .D#j        .D#j     
      G#t      E#t              .D#;   E#t      .E##E  LK:    t#E   ,WK,        ,WK,      
       t       E#t                tt   ..         G#E  i       tDj  EG.         EG.       
                                                   fE               ,           ,         
                                                    ,                                     
[/red]
[white]Version: {version}[/white]
'''.format(version=VERSION)

class OpenXSS:
    """
    OpenXSS - Modern, Modular XSS Scanner
    Features:
    - Plugin-based architecture
    - Smart payload engine
    - Context-aware fuzzing
    - WAF detection and bypass
    - Payload obfuscation
    """
    
    def __init__(self):
        self.console = Console()
        self.console.print(BANNER)
        self.logger = self._setup_logging()
        self.plugin_manager = PluginManager()
        self.payload_obfuscator = PayloadObfuscator()
        
    def _setup_logging(self) -> logging.Logger:
        """Configure logging."""
        logger = logging.getLogger("OpenXSS")
        logger.setLevel(logging.INFO)
        
        # Console handler
        console = logging.StreamHandler()
        console.setLevel(logging.INFO)
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        console.setFormatter(formatter)
        logger.addHandler(console)
        
        return logger
        
    def _setup_directories(self):
        """Create necessary directories and default files if they don't exist."""
        # Create directories
        dirs = {
            "data": ["params.txt", "xss_payloads.txt"],
            "plugins": ["__init__.py"],
            "core": ["__init__.py"],
            "reports": [],
            "db": ["wafSignatures.json", "definitions.json"]
        }
        
        for dir_name, files in dirs.items():
            dir_path = Path(dir_name)
            dir_path.mkdir(parents=True, exist_ok=True)
            
            # Create necessary files
            for file in files:
                file_path = dir_path / file
                if not file_path.exists():
                    file_path.touch()
                    
        self.logger.info("Created directory structure")
        
    def _install_dependencies(self):
        """Install required Python packages."""
        try:
            import pkg_resources
            import subprocess
            
            # Core dependencies
            core_deps = [
                "aiohttp>=3.8.0",
                "pyyaml>=6.0",
                "rich>=13.0.0",
                "requests>=2.28.0",
                "tld>=0.12.6",
                "fuzzywuzzy>=0.18.0",
                "python-Levenshtein>=0.12.2",  # For better fuzzywuzzy performance
                "dataclasses>=0.6",
                "typing-extensions>=4.0.0",
                "asyncio>=3.4.3",
                "beautifulsoup4>=4.9.3",  # For HTML parsing
                "playwright>=1.40.0",      # For DOM scanning
            ]
            
            # Check what's installed
            installed = {pkg.key: pkg.version for pkg in pkg_resources.working_set}
            to_install = []
            
            for dep in core_deps:
                pkg_name = dep.split('>=')[0]
                if pkg_name not in installed:
                    to_install.append(dep)
                    
            if to_install:
                self.logger.info("Installing missing dependencies...")
                subprocess.check_call([sys.executable, "-m", "pip", "install"] + to_install)
                
            # Install playwright browsers
            if 'playwright' in installed:
                self.logger.info("Installing Playwright browsers...")
                subprocess.check_call([sys.executable, "-m", "playwright", "install"])
                
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to install dependencies: {str(e)}")
            return False
            
    def _setup_config(self):
        """Create default configuration file if it doesn't exist."""
        config_path = Path("config.yaml")
        if not config_path.exists():
            default_config = {
                "param_bruteforcer": {
                    "wordlist": "data/params.txt",
                    "concurrent_requests": 10,
                    "timeout": 10,
                    "test_payload": "<script>alert(1)</script>"
                },
                "wordlist_scanner": {
                    "wordlist": "data/xss_payloads.txt",
                    "concurrent_requests": 10,
                    "timeout": 10,
                    "use_obfuscation": True,
                    "encoding_types": ["html", "unicode", "js_escape", "url", "base64"]
                },
                "advanced_scanner": {
                    "payloads_file": "data/xss_payloads.txt",
                    "max_payloads": 100,
                    "timeout": 30,
                    "detect_waf": True,
                    "use_obfuscation": True,
                    "encoding_types": ["html", "unicode"],
                    "waf_threshold": 0.7,
                    "max_retries": 3,
                    "delay_between_requests": 0.1
                },
                "crawler": {
                    "max_depth": 3,
                    "max_pages": 100,
                    "allowed_domains": [],
                    "exclude_patterns": []
                },
                "dom_scanner": {
                    "timeout": 30,
                    "screenshot_dir": "reports/screenshots",
                    "browser": "chromium"
                },
                "waf_detector": {
                    "signatures_file": "db/wafSignatures.json",
                    "detection_threshold": 0.8
                },
                "logging": {
                    "level": "INFO",
                    "file": "openxss.log"
                },
                "http": {
                    "timeout": 30,
                    "max_retries": 3,
                    "user_agent": f"OpenXSS Scanner v{VERSION}",
                    "headers": {
                        "Accept": "*/*",
                        "Connection": "keep-alive"
                    }
                }
            }
            
            import yaml
            with open(config_path, 'w') as f:
                yaml.dump(default_config, f, default_flow_style=False)
                
            self.logger.info("Created default configuration file")
            
    def _setup_databases(self):
        """Initialize database files with default content."""
        # WAF signatures
        waf_sigs_path = Path("db/wafSignatures.json")
        if not waf_sigs_path.exists() or waf_sigs_path.stat().st_size == 0:
            default_sigs = {
                "Cloudflare": {
                    "page_title": "Attention Required! | Cloudflare",
                    "headers": ["cf-ray", "cf-cache-status"],
                    "body": ["Sorry, you have been blocked", "Ray ID:"]
                },
                "ModSecurity": {
                    "headers": ["mod_security", "mod_security_crs"],
                    "body": ["ModSecurity Action", "ModSecurity Rule"]
                }
                # Add more WAF signatures as needed
            }
            
            with open(waf_sigs_path, 'w') as f:
                json.dump(default_sigs, f, indent=2)
                
        # XSS definitions
        defs_path = Path("db/definitions.json")
        if not defs_path.exists() or defs_path.stat().st_size == 0:
            default_defs = {
                "contexts": {
                    "html": {
                        "patterns": ["<[^>]*>"],
                        "payloads": ["<script>alert(1)</script>"]
                    },
                    "javascript": {
                        "patterns": ["<script[^>]*>", "on\\w+\\s*="],
                        "payloads": ["';alert(1);//"]
                    },
                    "attribute": {
                        "patterns": ["\\s\\w+\\s*=\\s*['\"]"],
                        "payloads": ["\" onmouseover=alert(1) x=\""]
                    }
                }
            }
            
            with open(defs_path, 'w') as f:
                json.dump(default_defs, f, indent=2)
                
        self.logger.info("Initialized database files")
        
    def _setup_wordlists(self):
        """Set up default wordlists if they don't exist."""
        # Parameters wordlist
        params_path = Path("data/params.txt")
        if not params_path.exists() or params_path.stat().st_size == 0:
            default_params = """id
q
s
search
query
page
keywords
cmd
search_string
lang
keyword
year
view
email
type
name
p
month
image
list_type
url
terms
categoryid
key
l
begindate
enddate
title"""
            
            with open(params_path, 'w') as f:
                f.write(default_params)
                
        # XSS payloads wordlist
        payloads_path = Path("data/xss_payloads.txt")
        if not payloads_path.exists() or payloads_path.stat().st_size == 0:
            default_payloads = """<script>alert(1)</script>
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
javascript:alert(1)
';alert(1);//
\";alert(1);//
</script><script>alert(1)</script>
<img src=x onerror="javascript:alert(1)">
<svg/onload=alert(1)>
<iframe src="javascript:alert(1)">
<body onload=alert(1)>
<details open ontoggle=alert(1)>
<select autofocus onfocus=alert(1)>
<marquee onstart=alert(1)>
<video src=1 onerror=alert(1)>
<audio src=1 onerror=alert(1)>
<input autofocus onfocus=alert(1)>
<form action="javascript:alert(1)"><input type=submit>
<isindex action="javascript:alert(1)" type=submit value=XSS>
<object data="javascript:alert(1)">
<embed src="javascript:alert(1)">"""
            
            with open(payloads_path, 'w') as f:
                f.write(default_payloads)
                
        self.logger.info("Set up wordlists")
        
    def setup(self):
        """Run complete setup process."""
        self.logger.info("Starting OpenXSS setup...")
        
        # Create directory structure
        self._setup_directories()
        
        # Install dependencies
        if not self._install_dependencies():
            self.logger.error("Failed to install dependencies")
            return False
            
        # Create default config
        self._setup_config()
        
        # Initialize databases
        self._setup_databases()
        
        # Set up wordlists
        self._setup_wordlists()
        
        self.logger.info("Setup complete! You can now start using OpenXSS.")
        return True

    def _check_requirements(self):
        """Verify all required dependencies are installed."""
        requirements = [
            "aiohttp",  # For async HTTP requests
            "pyyaml",   # For config files
            "rich",     # For terminal output
            "requests", # For updates
            "tld",      # For URL parsing
            "fuzzywuzzy" # For fuzzy matching
        ]
        
        missing = []
        for req in requirements:
            try:
                __import__(req)
            except ImportError:
                missing.append(req)
                
        if missing:
            self.logger.error(
                f"Missing required packages: {', '.join(missing)}. "
                f"Please install using: pip install {' '.join(missing)}"
            )
            sys.exit(1)
            
    def _load_config(self, config_file: str) -> Dict[str, Any]:
        """Load configuration from YAML file."""
        import yaml
        
        try:
            with open(config_file) as f:
                return yaml.safe_load(f)
        except Exception as e:
            self.logger.error(f"Error loading config file: {str(e)}")
            return {}

    async def update(self):
        """Check for updates and install if available."""
        import requests
        
        try:
            self.logger.info("Checking for updates...")
            r = requests.get("https://api.github.com/repos/IlumCI/OpenXSS/releases/latest")
            latest = r.json()["tag_name"]
            
            if latest > VERSION:
                self.logger.info(f"Update available: {latest}")
                if input("Would you like to update? [y/N] ").lower() == 'y':
                    os.system("git pull")
                    self.logger.info("Update complete! Please restart OpenXSS")
                    sys.exit(0)
            else:
                self.logger.info("OpenXSS is up to date!")
        except Exception as e:
            self.logger.error(f"Update check failed: {str(e)}")
            
    async def scan(self, args: argparse.Namespace):
        """Execute the scan based on command line arguments."""
        # Load configurations
        config = self._load_config(args.config)
        self.plugin_manager.load_configs(args.config)
        
        # Update proxy settings if specified
        if args.proxy:
            os.environ['HTTP_PROXY'] = args.proxy
            os.environ['HTTPS_PROXY'] = args.proxy
            
        # Prepare scan parameters
        params = {}
        if args.params:
            for param in args.params:
                name, value = param.split("=", 1)
                params[name] = value
                
        # Add custom headers
        headers = {}
        if args.headers:
            try:
                headers = json.loads(args.headers)
            except:
                self.logger.warning("Invalid headers format, using default")
                
        # Run plugins based on mode
        if args.plugin:
            # Run specific plugin
            result = await self.plugin_manager.run_plugin(
                args.plugin,
                args.target,
                params,
                headers=headers,
                delay=args.delay
            )
            if result:
                self._output_result(result)
        else:
            # Run all plugins
            results = await self.plugin_manager.run_all_plugins(
                args.target,
                params,
                parallel=not args.sequential,
                delay=args.delay,
                headers=headers
            )
            for result in results.values():
                self._output_result(result)
                
    def _output_result(self, result: Dict[str, Any]):
        """Format and display scan results."""
        from rich.table import Table
        
        # Create results table
        table = Table(show_header=True)
        table.add_column("Plugin")
        table.add_column("Status")
        table.add_column("Findings")
        table.add_column("Time")
        
        status = "✅" if result.success else "❌"
        findings = len(result.findings)
        time = f"{result.execution_time:.2f}s"
        
        table.add_row(result.plugin_name, status, str(findings), time)
        self.console.print(table)
        
        # Show findings details
        if result.findings:
            findings_table = Table(show_header=True)
            findings_table.add_column("Type")
            findings_table.add_column("Details")
            
            for finding in result.findings:
                findings_table.add_row(
                    finding.get("reflection_type", "unknown"),
                    str(finding)
                )
            self.console.print(findings_table)
            
        # Show errors if any
        if result.errors:
            self.console.print("[red]Errors:[/red]")
            for error in result.errors:
                self.console.print(f"  - {error}")

    def _show_xss_tutorial(self, console: Console) -> None:
        """Show interactive XSS tutorial."""
        # Get tutorial content
        tutorial = self._get_xss_intro()
        
        # Show main content
        console.print(Markdown(tutorial['text']))
        
        # Interactive examples
        if Confirm.ask("\nWould you like to try some interactive examples?", default=True):
            interactive = tutorial['interactive']
            console.print(f"\n[bold]{interactive['title']}[/bold]")
            console.print(interactive['description'])
            
            for step in interactive['steps']:
                console.print(f"\n[cyan]Step: {step['name']}[/cyan]")
                console.print(f"Input: [yellow]{step['input']}[/yellow]")
                console.print(f"Description: {step['description']}")
                if Confirm.ask("Try next example?", default=True):
                    continue
                else:
                    break
                    
        # Show XSS types
        if Confirm.ask("\nWould you like to learn about different types of XSS?", default=True):
            types = self._get_xss_types()
            console.print(Markdown(types['text']))
            
            # Interactive type identification
            if Confirm.ask("\nWould you like to practice identifying XSS types?", default=True):
                interactive = types['interactive']
                console.print(f"\n[bold]{interactive['title']}[/bold]")
                console.print(interactive['description'])
                
                for scenario in interactive['scenarios']:
                    console.print(f"\n[cyan]Scenario: {scenario['name']}[/cyan]")
                    console.print("Code:")
                    console.print(Panel(scenario['code']))
                    
                    answer = Prompt.ask(
                        "What type of XSS is this?",
                        choices=["Reflected", "Stored", "DOM-Based", "Universal"],
                        default="Reflected"
                    )
                    
                    if answer.lower() == scenario['type'].lower():
                        console.print("[green]Correct![/green]")
                    else:
                        console.print(f"[red]Not quite. This is {scenario['type']} XSS.[/red]")
                    console.print(f"Explanation: {scenario['explanation']}")
                    
                    if not Confirm.ask("Continue to next scenario?", default=True):
                        break

    def _run_wizard(self) -> Dict:
        """Run the interactive configuration wizard."""
        console = Console()
        config = {}

        # Welcome message
        console.print("\n[bold green]Welcome to OpenXSS Wizard! 🧙‍♂️[/bold green]")
        console.print("[cyan]I'll help you set up your scan configuration.[/cyan]\n")

        # Educational Section
        if Confirm.ask("\nWould you like to learn about XSS before starting?", default=True):
            self._show_xss_tutorial(console)

        # Target Selection
        console.print("\n[bold]Step 1: Target Selection 🎯[/bold]")
        target_type = Prompt.ask(
            "How would you like to specify targets?",
            choices=["single", "list", "crawl"],
            default="single"
        )

        if target_type == "single":
            config['url'] = Prompt.ask("Enter the target URL")
        elif target_type == "list":
            config['list'] = Prompt.ask("Enter the path to your targets file")
        else:
            config['url'] = Prompt.ask("Enter the starting URL for crawling")
            config['crawl'] = True
            config['depth'] = int(Prompt.ask("Enter crawling depth", default="2"))

        # Scan Mode
        console.print("\n[bold]Step 2: Scan Mode Selection 🚀[/bold]")
        scan_mode = Prompt.ask(
            "Choose your scan mode",
            choices=["stealth", "normal", "aggressive"],
            default="normal"
        )

        # Configure scan based on mode
        if scan_mode == "stealth":
            config.update({
                'threads': 1,
                'timeout': 60,
                'waf_level': 3,
                'smart': True,
                'obfuscate': True
            })
            console.print("[dim]Using stealthy configuration with slow scanning and maximum evasion...[/dim]")
        elif scan_mode == "aggressive":
            config.update({
                'threads': 20,
                'timeout': 10,
                'waf_level': 1,
                'chain_length': 3
            })
            console.print("[dim]Using aggressive configuration with fast scanning and multiple payloads...[/dim]")
        else:
            config.update({
                'threads': 10,
                'timeout': 30,
                'waf_level': 2
            })
            console.print("[dim]Using balanced configuration...[/dim]")

        # Advanced Features
        console.print("\n[bold]Step 3: Advanced Features 🛠[/bold]")
        
        if Confirm.ask("Would you like to enable DOM XSS scanning?", default=True):
            config['dom'] = True
            console.print("[dim]DOM XSS scanning enabled[/dim]")

        if Confirm.ask("Would you like to enable blind XSS detection?"):
            config['blind'] = True
            webhook = Prompt.ask("Enter your webhook URL for blind XSS callbacks (optional)")
            if webhook:
                config['webhook'] = webhook
            console.print("[dim]Blind XSS detection enabled[/dim]")

        # Proxy Configuration
        console.print("\n[bold]Step 4: Proxy Configuration 🔄[/bold]")
        proxy_choice = Prompt.ask(
            "Would you like to use a proxy?",
            choices=["none", "burp", "zap", "custom"],
            default="none"
        )

        if proxy_choice == "burp":
            config['proxy'] = "http://127.0.0.1:8080"
            console.print("[dim]Using Burp Suite proxy (localhost:8080)[/dim]")
        elif proxy_choice == "zap":
            config['proxy'] = "http://127.0.0.1:8090"
            console.print("[dim]Using OWASP ZAP proxy (localhost:8090)[/dim]")
        elif proxy_choice == "custom":
            config['proxy'] = Prompt.ask("Enter your proxy URL (e.g., http://127.0.0.1:8080)")

        # Output Configuration
        console.print("\n[bold]Step 5: Output Configuration 📝[/bold]")
        if Confirm.ask("Would you like to save the results to a file?", default=True):
            config['output'] = Prompt.ask(
                "Enter the output file path",
                default="openxss_report.html"
            )
            config['format'] = Prompt.ask(
                "Choose output format",
                choices=["html", "json", "csv", "burp"],
                default="html"
            )

        # Set up plugin configurations
        plugin_configs = {
            "wordlist_scanner": {
                "wordlist": "data/xss_payloads.txt",
                "concurrent_requests": config.get('threads', 10),
                "timeout": config.get('timeout', 30),
                "use_obfuscation": True,
                "encoding_types": ["html", "unicode"]
            },
            "advanced_scanner": {
                "payloads_file": "data/xss_payloads.txt",
                "max_payloads": 100,
                "timeout": config.get('timeout', 30),
                "detect_waf": True,
                "use_obfuscation": config.get('obfuscate', True),
                "encoding_types": ["html", "unicode"],
                "waf_threshold": 0.7,
                "max_retries": 3,
                "delay_between_requests": 0.1
            },
            "param_bruteforcer": {
                "wordlist": "data/params.txt",
                "concurrent_requests": config.get('threads', 10),
                "timeout": config.get('timeout', 30),
                "test_payload": "<script>alert(1)</script>"
            }
        }

        # Update plugin manager configurations
        self.plugin_manager.configs.update(plugin_configs)

        # Summary
        console.print("\n[bold green]Configuration Summary ✨[/bold green]")
        summary_table = Table(show_header=True, header_style="bold magenta")
        summary_table.add_column("Setting")
        summary_table.add_column("Value")

        for key, value in config.items():
            summary_table.add_row(key, str(value))

        console.print(summary_table)

        if Confirm.ask("\nWould you like to start the scan with these settings?", default=True):
            return config
        else:
            console.print("[yellow]Wizard cancelled. Exiting...[/yellow]")
            sys.exit(0)

    def _get_xss_intro(self) -> Dict[str, str]:
        return {
            'text': """
# Cross-Site Scripting (XSS)

Cross-Site Scripting (XSS) is a security vulnerability that allows attackers to inject malicious scripts into web pages viewed by other users. 

🔍 **Key Points:**
- Occurs when applications include untrusted data in web pages without proper validation
- Executes in the victim's browser context
- Can steal cookies, session tokens, and other sensitive information
- Ranked in OWASP Top 10 Web Application Security Risks

💡 **How it Works:**
1. Attacker finds an input field that reflects data in the page
2. Attacker injects malicious JavaScript code
3. Victim visits the compromised page
4. Malicious code executes in victim's browser

🎯 **Common Injection Points:**
- Search boxes
- Comment forms
- User profile fields
- URL parameters
- HTTP headers
- File uploads
- JSON/XML data

⚠️ **Impact Levels:**
1. **Low:** Popup alerts, page defacement
2. **Medium:** Session theft, keylogging
3. **High:** Account takeover, data exfiltration
4. **Critical:** Full system compromise

🛡️ **Detection Methods:**
1. Input reflection analysis
2. DOM manipulation tracking
3. Response header inspection
4. JavaScript execution monitoring
""",
            'interactive': {
                'title': "Interactive XSS Lab 🔬",
                'description': "Let's explore different XSS scenarios in a safe environment:",
                'steps': [
                    {
                        'name': "Basic Reflection",
                        'input': "hello",
                        'description': "Normal text is reflected as-is"
                    },
                    {
                        'name': "Script Injection",
                        'input': "<script>alert(1)</script>",
                        'description': "JavaScript execution attempt"
                    },
                    {
                        'name': "Attribute Injection",
                        'input': '" onmouseover="alert(1)',
                        'description': "Breaking out of HTML attributes"
                    },
                    {
                        'name': "HTML Injection",
                        'input': "<img src=x onerror=alert(1)>",
                        'description': "Injecting HTML elements"
                    },
                    {
                        'name': "JavaScript URI",
                        'input': "javascript:alert(1)",
                        'description': "Using JavaScript protocol"
                    }
                ]
            }
        }

    def _get_xss_types(self) -> Dict[str, str]:
        return {
            'text': """
# Types of XSS Attacks

## 1. Reflected XSS
🔄 **Characteristics:**
- Malicious script is reflected off the web server
- Payload is part of the victim's request
- Typically found in search results, error messages
- Requires victim to click a malicious link

📝 **Common Locations:**
- Search forms
- Error messages
- URL parameters
- HTTP headers
- Referrer tracking

🛠️ **Attack Methods:**
- URL manipulation
- Form submission
- Header injection
- Social engineering

## 2. Stored XSS
💾 **Characteristics:**
- Malicious script is stored on the target server
- Affects anyone who visits the infected page
- Persists until removed from storage
- Most dangerous type of XSS

📝 **Common Locations:**
- Comments sections
- User profiles
- Forum posts
- Product reviews
- Chat messages
- File metadata

🛠️ **Attack Methods:**
- Form submissions
- API requests
- File uploads
- Profile updates

## 3. DOM-Based XSS
🌐 **Characteristics:**
- Occurs in client-side JavaScript
- Modifies the DOM unsafely
- No server-side reflection
- Hard to detect with scanners

📝 **Common Sources:**
- URL fragments (#)
- Query parameters
- document.referrer
- window.name
- localStorage/sessionStorage
- postMessage data

🛠️ **Attack Methods:**
- URL fragment manipulation
- localStorage poisoning
- postMessage exploitation
- DOM element manipulation

## 4. Universal XSS (UXSS)
🌍 **Characteristics:**
- Exploits browser vulnerabilities
- Affects multiple domains
- Bypasses Same-Origin Policy
- Extremely powerful impact

📝 **Attack Vectors:**
- Browser extensions
- Protocol handlers
- Sandbox escapes
- Frame navigation
""",
            'interactive': {
                'title': "XSS Type Identification Lab 🔍",
                'description': "Let's practice identifying different types of XSS:",
                'scenarios': [
                    {
                        'name': "Search Result",
                        'code': '<p>Results for: <?=$_GET["q"]?></p>',
                        'type': "Reflected",
                        'explanation': "Input is immediately reflected in response"
                    },
                    {
                        'name': "User Comment",
                        'code': '<div class="comment"><?=$comment?></div>',
                        'type': "Stored",
                        'explanation': "Input is stored in database and displayed later"
                    },
                    {
                        'name': "Theme Selector",
                        'code': 'element.innerHTML = location.hash.slice(1)',
                        'type': "DOM-Based",
                        'explanation': "Vulnerability exists in client-side code"
                    },
                    {
                        'name': "Extension Popup",
                        'code': 'chrome.tabs.executeScript({code: params.data})',
                        'type': "Universal",
                        'explanation': "Affects browser context across origins"
                    }
                ]
            }
        }

def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description=f"""OpenXSS v{VERSION} - Modern Modular XSS Scanner
        
Basic Usage:
    python openxss.py -t https://example.com
    python openxss.py -t https://example.com -p param1=test

Advanced Usage:
    python openxss.py -t https://example.com --plugin wordlist_scanner --headers '{{"User-Agent": "Custom"}}' --proxy http://127.0.0.1:8080
    python openxss.py -t https://example.com -p param1=test param2=test --delay 0.5 --config custom_config.yaml
""",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    # Target arguments
    target_group = parser.add_argument_group('Target')
    target_group.add_argument(
        "-t", "--target",
        help="Target URL to scan",
        required=False
    )
    
    target_group.add_argument(
        "-p", "--params",
        help="Parameters to test (e.g., -p param1=test param2=test)",
        nargs="*",
        metavar="PARAM=VALUE"
    )
    
    # Scan configuration
    scan_group = parser.add_argument_group('Scan Configuration')
    scan_group.add_argument(
        "--plugin",
        help="Run specific plugin (e.g., wordlist_scanner, param_bruteforcer)",
        choices=["wordlist_scanner", "param_bruteforcer", "dom_scanner", "crawler", "waf_detector"]
    )
    
    scan_group.add_argument(
        "-c", "--config",
        help="Path to config file (default: config.yaml)",
        default="config.yaml"
    )
    
    scan_group.add_argument(
        "-s", "--sequential",
        help="Run plugins sequentially instead of parallel",
        action="store_true"
    )
    
    scan_group.add_argument(
        "-d", "--delay",
        help="Delay between requests in seconds (default: 0)",
        type=float,
        default=0
    )
    
    # HTTP options
    http_group = parser.add_argument_group('HTTP Options')
    http_group.add_argument(
        "--proxy",
        help="Proxy URL (e.g., http://127.0.0.1:8080)",
        metavar="URL"
    )
    
    http_group.add_argument(
        "--headers",
        help='Custom headers as JSON string (e.g., \'{"User-Agent": "Custom"}\')',
        metavar="JSON"
    )
    
    # Utility options
    util_group = parser.add_argument_group('Utility Options')
    util_group.add_argument(
        "--setup",
        help="Run first-time setup and installation",
        action="store_true"
    )
    
    util_group.add_argument(
        "--wizard",
        help="Interactive setup wizard to configure OpenXSS",
        action="store_true"
    )
    
    util_group.add_argument(
        "--update",
        help="Check for updates",
        action="store_true"
    )
    
    util_group.add_argument(
        "--examples",
        help="Show detailed usage examples",
        action="store_true"
    )
    
    args = parser.parse_args()
    
    # Initialize OpenXSS
    scanner = OpenXSS()
    
    # Run wizard if requested
    if args.wizard:
        config = scanner._run_wizard()
        if config:
            # Convert wizard config to scan arguments
            if 'url' in config:
                args.target = config['url']
            if 'proxy' in config:
                args.proxy = config['proxy']
            if 'threads' in config:
                args.threads = config['threads']
            if 'timeout' in config:
                args.timeout = config['timeout']
            # Add other config mappings as needed
            
            # Run the scan with the configured settings
            asyncio.run(scanner.scan(args))
        return
        
    # Show extended examples if requested
    if args.examples:
        print("""
OpenXSS Usage Examples
=====================

Basic Scans:
-----------
1. Basic scan of a URL:
   python openxss.py -t https://example.com

2. Scan with specific parameters:
   python openxss.py -t https://example.com -p username=test password=test

3. Scan with a single plugin:
   python openxss.py -t https://example.com --plugin wordlist_scanner

Advanced Scans:
-------------
4. Full scan with proxy and custom headers:
   python openxss.py -t https://example.com --proxy http://127.0.0.1:8080 --headers '{"User-Agent": "Mozilla/5.0", "X-Custom": "Value"}'

5. Scan with delay and custom config:
   python openxss.py -t https://example.com -p param1=test --delay 0.5 --config custom_config.yaml

6. Sequential plugin execution with all options:
   python openxss.py -t https://example.com -p param1=test param2=test --sequential --delay 1 --proxy http://127.0.0.1:8080 --headers '{"User-Agent": "Custom"}'

Utility Commands:
---------------
7. First-time setup:
   python openxss.py --setup

8. Check for updates:
   python openxss.py --update

Plugin-Specific Examples:
----------------------
9. Run DOM scanner:
   python openxss.py -t https://example.com --plugin dom_scanner

10. Run parameter bruteforcer:
    python openxss.py -t https://example.com --plugin param_bruteforcer

11. Run WAF detector:
    python openxss.py -t https://example.com --plugin waf_detector

12. Run crawler with depth control:
    python openxss.py -t https://example.com --plugin crawler -c config.yaml
    # In config.yaml:
    # crawler:
    #   max_depth: 3
    #   max_pages: 100

Configuration Examples:
--------------------
Example config.yaml:
```yaml
wordlist_scanner:
  wordlist: data/xss_payloads.txt
  concurrent_requests: 10
  timeout: 10
  use_obfuscation: true
  encoding_types:
    - html
    - unicode

param_bruteforcer:
  wordlist: data/params.txt
  concurrent_requests: 10
  timeout: 10
  test_payload: "<script>alert(1)</script>"

http:
  timeout: 30
  max_retries: 3
  user_agent: "OpenXSS Scanner v1.0"
```
""")
        return
        
    # Run setup if requested
    if args.setup:
        if scanner.setup():
            scanner.logger.info("OpenXSS is ready to use!")
            scanner.logger.info("Try running a scan with: python openxss.py -t <target_url>")
        return
        
    # Check for updates if requested
    if args.update:
        asyncio.run(scanner.update())
        return
        
    # Require target for scanning operations
    if not args.target and not (args.setup or args.update or args.examples or args.wizard):
        parser.error("the following arguments are required: -t/--target")
        
    # Run scan
    asyncio.run(scanner.scan(args))

if __name__ == "__main__":
    main()
