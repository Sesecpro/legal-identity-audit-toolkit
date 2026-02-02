"""
Sesecpro Compliance Engine - Compliance Scoring
================================================
Calculates weighted compliance scores based on findings.
"""
from typing import List
from core.models import Asset, TechnicalFinding, RiskLevel, ScanResult


class ComplianceScorer:
    """
    Calculates compliance scores based on findings severity.
    """

    # Weight multipliers for each risk level
    RISK_WEIGHTS = {
        RiskLevel.CRITICAL: 25,
        RiskLevel.HIGH: 15,
        RiskLevel.MEDIUM: 8,
        RiskLevel.LOW: 3,
        RiskLevel.INFO: 0  # INFO doesn't affect score
    }

    def calculate_score(self, scan_result: ScanResult) -> float:
        """
        Calculate compliance score from 0-100.
        100 = Perfect compliance, 0 = Severe non-compliance.
        """
        total_penalty = 0
        total_assets = len(scan_result.assets) or 1

        for asset in scan_result.assets:
            for finding in asset.findings:
                penalty = self.RISK_WEIGHTS.get(finding.risk_level, 0)
                # Additional penalty for compliance violations
                if finding.compliance_violations:
                    penalty *= 1.5
                total_penalty += penalty

        # Normalize score (cap penalty at 100)
        score = max(0, 100 - min(total_penalty, 100))

        # Bonus for having no critical/high findings
        critical_high_count = sum(
            1 for asset in scan_result.assets
            for finding in asset.findings
            if finding.risk_level in [RiskLevel.CRITICAL, RiskLevel.HIGH]
        )

        if critical_high_count == 0:
            score = min(100, score + 10)

        return round(score, 1)

    def get_score_grade(self, score: float) -> str:
        """Convert score to letter grade."""
        if score >= 90:
            return "A"
        elif score >= 80:
            return "B"
        elif score >= 70:
            return "C"
        elif score >= 60:
            return "D"
        else:
            return "F"

    def get_score_color(self, score: float) -> str:
        """Get color for score display."""
        if score >= 80:
            return "green"
        elif score >= 60:
            return "yellow"
        else:
            return "red"
