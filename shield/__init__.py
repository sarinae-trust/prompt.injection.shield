"""
Shield - Prompt Injection Protection Library

A comprehensive library to detect and sanitize prompt injection attacks
for LLM applications.
"""

__version__ = "0.1.0"
__author__ = "Shield Team"

from .detector import PromptInjectionDetector
from .sanitizer import PromptSanitizer
from .analyzer import SecurityAnalyzer

__all__ = [
    "PromptInjectionDetector",
    "PromptSanitizer",
    "SecurityAnalyzer",
]
