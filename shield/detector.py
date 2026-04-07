"""
Prompt Injection Detection Engine

Detects common prompt injection attack patterns.
"""

import re
from typing import Dict, List, Tuple
from enum import Enum


class ThreatLevel(Enum):
    """Threat severity levels"""
    SAFE = "safe"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class PromptInjectionDetector:
    """Detects prompt injection attempts in user inputs"""

    # Common injection patterns
    INJECTION_PATTERNS = {
        "ignore_instructions": r"(?i)(ignore|disregard|forget|override)\s+(all\s+)?(previous\s+)?(instructions|prompts|rules|guidelines)",
        "system_role_change": r"(?i)(you\s+are|you're|act\s+as|pretend|role\s+play|roleplay).*?(?:gpt|bot|assistant|model|ai|llm)",
        "direct_injection": r"(?i)(system|system\s+message|system\s+prompt|hidden|secret|real|actual):\s*",
        "prompt_extraction": r"(?i)(show|reveal|display|print|output|tell\s+me)\s+(the\s+)?(system\s+)?prompt",
        "jailbreak": r"(?i)(jailbreak|bypass|circumvent|exploit|hack)\s+(me|the\s+)?(?:security|filter|protection|rules)",
        "context_injection": r"(?i)(new\s+context|context\s+switch|reset\s+context|clear\s+context)",
        "instruction_override": r"(?i)(follow\s+this\s+instead|use\s+this\s+instruction|prioritize\s+this|execute\s+this)",
        "conditional_execution": r"(?i)(if\s+|assuming\s+|given\s+that\s+).*?(?:then|do|execute)",
        "translation_bypass": r"(?i)(translate\s+this\s+from|convert\s+from|decode|reverse)",
        "code_execution": r"(?i)(execute|eval|run|compile|import|require)\s*\(.*\)",
    }

    def __init__(self, strict_mode: bool = False):
        """
        Initialize the detector

        Args:
            strict_mode: If True, applies more aggressive detection
        """
        self.strict_mode = strict_mode
        self.detected_patterns: List[str] = []

    def detect(self, text: str) -> Tuple[bool, ThreatLevel, Dict[str, any]]:
        """
        Detect prompt injection attempts

        Args:
            text: Input text to analyze

        Returns:
            Tuple of (is_injection, threat_level, details)
        """
        self.detected_patterns = []
        threat_scores: Dict[str, float] = {}
        matches_found = []

        # Check each pattern
        for pattern_name, pattern in self.INJECTION_PATTERNS.items():
            if re.search(pattern, text):
                self.detected_patterns.append(pattern_name)
                threat_scores[pattern_name] = 1.0
                matches_found.append(pattern_name)

        # Calculate overall threat level
        threat_level = self._calculate_threat_level(threat_scores, len(text))
        is_injection = threat_level != ThreatLevel.SAFE

        details = {
            "is_injection": is_injection,
            "threat_level": threat_level.value,
            "patterns_matched": matches_found,
            "pattern_details": threat_scores,
            "text_length": len(text),
            "confidence": self._calculate_confidence(threat_scores),
        }

        return is_injection, threat_level, details

    def _calculate_threat_level(self, threat_scores: Dict, text_length: int) -> ThreatLevel:
        """Calculate threat level based on patterns found"""
        if not threat_scores:
            return ThreatLevel.SAFE

        score = sum(threat_scores.values())

        if score >= 3:
            return ThreatLevel.CRITICAL
        elif score >= 2:
            return ThreatLevel.HIGH
        elif score >= 1.5:
            return ThreatLevel.MEDIUM
        elif score >= 1:
            return ThreatLevel.LOW
        else:
            return ThreatLevel.SAFE

    def _calculate_confidence(self, threat_scores: Dict) -> float:
        """Calculate confidence level (0-1)"""
        if not threat_scores:
            return 0.0
        return min(1.0, sum(threat_scores.values()) / len(threat_scores))

    def get_detailed_report(self, text: str) -> Dict:
        """Get a detailed security report"""
        is_injection, threat_level, details = self.detect(text)

        report = {
            "text": text[:100] + "..." if len(text) > 100 else text,
            "is_dangerous": is_injection,
            "threat_level": threat_level.value,
            "confidence_score": details["confidence"],
            "patterns_detected": details["patterns_matched"],
            "recommendations": self._get_recommendations(threat_level),
        }

        return report

    def _get_recommendations(self, threat_level: ThreatLevel) -> List[str]:
        """Get security recommendations based on threat level"""
        recommendations = {
            ThreatLevel.SAFE: ["Input appears safe to process"],
            ThreatLevel.LOW: [
                "Input may contain suspicious patterns",
                "Consider additional validation",
            ],
            ThreatLevel.MEDIUM: [
                "Input contains potential injection patterns",
                "Recommend manual review before processing",
                "Consider rejecting this input",
            ],
            ThreatLevel.HIGH: [
                "Input contains multiple injection patterns",
                "Strongly recommend rejecting this input",
                "Log this attempt for security analysis",
            ],
            ThreatLevel.CRITICAL: [
                "Critical threat detected - likely prompt injection",
                "REJECT immediately",
                "Alert security team",
                "Log all details for investigation",
            ],
        }

        return recommendations.get(threat_level, [])
