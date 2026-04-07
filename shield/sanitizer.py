"""
Prompt Input Sanitization Module

Sanitizes and cleans user inputs to prevent prompt injection.
"""

import re
from typing import Dict, List, Optional


class PromptSanitizer:
    """Sanitizes user inputs to prevent prompt injection attacks"""

    # Characters to escape
    DANGEROUS_CHARS = {
        "\n": "\\n",
        "\r": "\\r",
        "\t": "\\t",
        '"': '\\"',
        "'": "\\'",
        "`": "\\`",
    }

    # Keywords to remove or flag
    RISKY_KEYWORDS = [
        "system",
        "admin",
        "root",
        "sudo",
        "execute",
        "eval",
        "exec",
        "import",
        "require",
        "delete",
        "drop",
    ]

    def __init__(self, aggressive: bool = False):
        """
        Initialize sanitizer

        Args:
            aggressive: If True, applies more strict sanitization
        """
        self.aggressive = aggressive
        self.sanitization_log: List[Dict] = []

    def sanitize(self, text: str, preserve_formatting: bool = True) -> str:
        """
        Sanitize input text

        Args:
            text: Input text to sanitize
            preserve_formatting: If True, preserves newlines and basic formatting

        Returns:
            Sanitized text
        """
        if not text or not isinstance(text, str):
            return ""

        sanitized = text

        # Remove null bytes and control characters
        sanitized = self._remove_control_chars(sanitized)

        # Remove potential code injection
        sanitized = self._remove_code_patterns(sanitized)

        # Escape special characters
        if not preserve_formatting:
            sanitized = self._escape_special_chars(sanitized)

        # Remove or replace risky keywords
        sanitized = self._handle_risky_keywords(sanitized)

        # Limit length to prevent overflow attacks
        sanitized = self._limit_length(sanitized)

        return sanitized

    def _remove_control_chars(self, text: str) -> str:
        """Remove control characters and null bytes"""
        # Remove null bytes
        text = text.replace("\x00", "")

        # Remove other control characters (except newline, tab, carriage return)
        text = "".join(
            char
            for char in text
            if ord(char) >= 32 or char in "\n\t\r"
        )

        return text

    def _remove_code_patterns(self, text: str) -> str:
        """Remove potential code injection patterns"""
        # Remove common code execution patterns
        code_patterns = [
            r"<script[^>]*>.*?</script>",  # JavaScript
            r"{{.*?}}",  # Template injection
            r"{%.*?%}",  # Jinja/template
            r"\$\{.*?\}",  # Expression injection
            r"<!--.*?-->",  # Comments
        ]

        for pattern in code_patterns:
            text = re.sub(pattern, "", text, flags=re.DOTALL | re.IGNORECASE)

        return text

    def _escape_special_chars(self, text: str) -> str:
        """Escape special characters"""
        for char, escaped in self.DANGEROUS_CHARS.items():
            text = text.replace(char, escaped)

        return text

    def _handle_risky_keywords(self, text: str, replacement: str = "[REDACTED]") -> str:
        """
        Handle risky keywords

        Args:
            text: Input text
            replacement: Replacement text for detected keywords

        Returns:
            Text with keywords replaced
        """
        if self.aggressive:
            for keyword in self.RISKY_KEYWORDS:
                # Case-insensitive replacement with word boundaries
                pattern = r"\b" + re.escape(keyword) + r"\b"
                text = re.sub(pattern, replacement, text, flags=re.IGNORECASE)

        return text

    def _limit_length(self, text: str, max_length: int = 5000) -> str:
        """Limit text length to prevent overflow attacks"""
        if len(text) > max_length:
            return text[:max_length]
        return text

    def create_safe_prompt(
        self,
        system_prompt: str,
        user_input: str,
        separator: str = "\n\n---\n\n",
    ) -> str:
        """
        Create a safe prompt combining system and user input

        Args:
            system_prompt: System instructions
            user_input: User-provided input
            separator: Separator between system and user input

        Returns:
            Safe combined prompt
        """
        sanitized_input = self.sanitize(user_input)
        safe_prompt = f"{system_prompt}{separator}USER INPUT:\n{sanitized_input}"
        return safe_prompt

    def sanitize_dict(self, data: Dict, recursive: bool = True) -> Dict:
        """
        Sanitize a dictionary of inputs

        Args:
            data: Dictionary to sanitize
            recursive: If True, sanitizes nested dicts

        Returns:
            Sanitized dictionary
        """
        sanitized = {}

        for key, value in data.items():
            if isinstance(value, str):
                sanitized[key] = self.sanitize(value)
            elif isinstance(value, dict) and recursive:
                sanitized[key] = self.sanitize_dict(value, recursive)
            elif isinstance(value, list) and recursive:
                sanitized[key] = [
                    self.sanitize(item) if isinstance(item, str)
                    else self.sanitize_dict(item) if isinstance(item, dict)
                    else item
                    for item in value
                ]
            else:
                sanitized[key] = value

        return sanitized

    def get_sanitization_stats(self) -> Dict:
        """Get statistics about sanitization operations"""
        total_ops = len(self.sanitization_log)
        
        stats = {
            "total_operations": total_ops,
            "aggressive_mode": self.aggressive,
        }

        return stats
