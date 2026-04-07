"""
Security Analysis Module

Comprehensive security analysis combining detection and sanitization.
"""

from typing import Dict, List, Tuple, Optional
from .detector import PromptInjectionDetector, ThreatLevel
from .sanitizer import PromptSanitizer


class SecurityAnalyzer:
    """Combined security analysis for prompt injection protection"""

    def __init__(self, strict_detection: bool = False, aggressive_sanitization: bool = False):
        """
        Initialize the security analyzer

        Args:
            strict_detection: Enable strict detection mode
            aggressive_sanitization: Enable aggressive sanitization
        """
        self.detector = PromptInjectionDetector(strict_mode=strict_detection)
        self.sanitizer = PromptSanitizer(aggressive=aggressive_sanitization)
        self.analysis_history: List[Dict] = []

    def analyze(self, text: str, auto_sanitize: bool = False) -> Dict:
        """
        Perform complete security analysis

        Args:
            text: Input text to analyze
            auto_sanitize: If True, automatically sanitizes unsafe input

        Returns:
            Comprehensive analysis report
        """
        # Detection phase
        is_injection, threat_level, detection_details = self.detector.detect(text)

        # Determine action based on threat level
        action = self._determine_action(threat_level)

        sanitized_text = None
        if auto_sanitize and threat_level != ThreatLevel.SAFE:
            sanitized_text = self.sanitizer.sanitize(text)

        analysis = {
            "timestamp": self._get_timestamp(),
            "input_length": len(text),
            "is_injection_detected": is_injection,
            "threat_level": threat_level.value,
            "threat_scores": detection_details["pattern_details"],
            "patterns_detected": detection_details["patterns_matched"],
            "confidence": detection_details["confidence"],
            "recommended_action": action,
            "original_text": text[:100] + "..." if len(text) > 100 else text,
            "sanitized_text": sanitized_text[:100] + "..." if sanitized_text and len(sanitized_text) > 100 else sanitized_text,
            "recommendations": self.detector._get_recommendations(threat_level),
        }

        self.analysis_history.append(analysis)
        return analysis

    def batch_analyze(self, texts: List[str], auto_sanitize: bool = False) -> List[Dict]:
        """
        Analyze multiple texts

        Args:
            texts: List of input texts
            auto_sanitize: If True, automatically sanitizes unsafe inputs

        Returns:
            List of analysis reports
        """
        return [self.analyze(text, auto_sanitize) for text in texts]

    def verify_prompt_safety(
        self,
        system_prompt: str,
        user_input: str,
        allow_medium_threat: bool = False,
    ) -> Tuple[bool, Dict]:
        """
        Verify if a combined prompt is safe to use

        Args:
            system_prompt: System instructions
            user_input: User-provided input
            allow_medium_threat: If True, allows medium threat level

        Returns:
            Tuple of (is_safe, details)
        """
        # Analyze user input
        user_analysis = self.analyze(user_input)

        # Check threat level
        threat_level = ThreatLevel[user_analysis["threat_level"].upper()]

        if threat_level == ThreatLevel.CRITICAL:
            is_safe = False
        elif threat_level == ThreatLevel.HIGH:
            is_safe = False
        elif threat_level == ThreatLevel.MEDIUM and not allow_medium_threat:
            is_safe = False
        else:
            is_safe = True

        details = {
            "is_safe": is_safe,
            "threat_level": threat_level.value,
            "patterns_detected": user_analysis["patterns_detected"],
            "safe_prompt": None,
        }

        if is_safe:
            details["safe_prompt"] = self.sanitizer.create_safe_prompt(
                system_prompt, user_input
            )

        return is_safe, details

    def _determine_action(self, threat_level: ThreatLevel) -> str:
        """Determine recommended action based on threat level"""
        actions = {
            ThreatLevel.SAFE: "ACCEPT",
            ThreatLevel.LOW: "REVIEW",
            ThreatLevel.MEDIUM: "REVIEW_AND_SANITIZE",
            ThreatLevel.HIGH: "SANITIZE_OR_REJECT",
            ThreatLevel.CRITICAL: "REJECT",
        }

        return actions.get(threat_level, "UNKNOWN")

    def _get_timestamp(self) -> str:
        """Get current timestamp"""
        from datetime import datetime
        return datetime.now().isoformat()

    def get_security_report(self) -> Dict:
        """Generate comprehensive security report from history"""
        if not self.analysis_history:
            return {
                "total_analyses": 0,
                "injections_detected": 0,
                "threats_by_level": {},
            }

        total = len(self.analysis_history)
        injections = sum(1 for a in self.analysis_history if a["is_injection_detected"])

        threats_by_level = {}
        for analysis in self.analysis_history:
            level = analysis["threat_level"]
            threats_by_level[level] = threats_by_level.get(level, 0) + 1

        report = {
            "total_analyses": total,
            "injections_detected": injections,
            "injection_rate": round(injections / total * 100, 2) if total > 0 else 0,
            "threats_by_level": threats_by_level,
            "average_confidence": round(
                sum(a["confidence"] for a in self.analysis_history) / total, 2
            ) if total > 0 else 0,
        }

        return report

    def reset_history(self):
        """Clear analysis history"""
        self.analysis_history = []
