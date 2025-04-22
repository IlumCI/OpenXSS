from core.context_plugin import ContextPlugin

class ReactContextPlugin(ContextPlugin):
    """
    Plugin for detecting React-specific contexts and providing appropriate mutations.
    """
    
    def __init__(self):
        super().__init__(
            name="react_context",
            description="Detects React-specific contexts and provides appropriate mutations"
        )
        
        # Register patterns for React contexts
        self.register_pattern(
            "jsx_expression",
            r'\{[^}]*\}',
            "jsx_expression"
        )
        self.register_pattern(
            "jsx_attribute",
            r'[a-zA-Z0-9-]+=',
            "jsx_attribute"
        )
        self.register_pattern(
            "dangerously_set_inner_html",
            r'dangerouslySetInnerHTML\s*=',
            "dangerous_html"
        )
        
        # Register mutation rules
        self.register_mutation_rule("jsx_expression", [
            "jsx_expression_escape",
            "jsx_expression_unicode",
            "jsx_expression_template"
        ])
        self.register_mutation_rule("jsx_attribute", [
            "jsx_attribute_escape",
            "jsx_attribute_unicode"
        ])
        self.register_mutation_rule("dangerous_html", [
            "html_entity",
            "unicode_escape",
            "js_template"
        ])
        
        # Register boundaries
        self.register_boundary("{")
        self.register_boundary("}")
        self.register_boundary("=")
        self.register_boundary("'")
        self.register_boundary('"') 