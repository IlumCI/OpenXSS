from core.context_plugin import ContextPlugin

class JavaScriptPlugin(ContextPlugin):
    """
    Plugin for detecting JavaScript contexts and patterns.
    """
    
    def __init__(self):
        super().__init__(
            name="javascript",
            description="Detects JavaScript code blocks and common patterns"
        )
        
        # Register patterns
        self.register_pattern("script_tag", r"<script[^>]*>.*?</script>")
        self.register_pattern("inline_script", r"javascript:[^\"']*")
        self.register_pattern("event_handler", r"on\w+\s*=\s*[\"'][^\"']*[\"']")
        self.register_pattern("function_call", r"\w+\([^)]*\)")
        self.register_pattern("string_literal", r"[\"'][^\"']*[\"']")
        
        # Register mutations
        self.register_mutation("script_tag", "<script>alert(1)</script>")
        self.register_mutation("inline_script", "javascript:alert(1)")
        self.register_mutation("event_handler", "onclick=\"alert(1)\"")
        self.register_mutation("function_call", "alert(1)")
        self.register_mutation("string_literal", "\"alert(1)\"")
        
        # Register boundaries
        self.register_boundary(";")
        self.register_boundary("{")
        self.register_boundary("}")
        self.register_boundary("(")
        self.register_boundary(")") 