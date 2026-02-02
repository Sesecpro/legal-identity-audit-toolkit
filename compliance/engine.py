"""
Sesecpro Compliance Engine - Compliance Engine
===============================================
Translates technical findings into regulatory violations.
"""
from typing import List
from core.models import TechnicalFinding, ComplianceStandard, Violation
from compliance.rules import NIS2_MAPPINGS, DORA_MAPPINGS


class ComplianceEngine:
    """
    Maps technical security findings to regulatory compliance violations.
    Business Context: Automates the gap analysis between security posture
    and regulatory requirements.
    """

    def evaluate_findings(self, findings: List[TechnicalFinding]) -> None:
        """
        Evaluates findings and appends compliance violations.
        Modifies findings in-place.
        """
        for finding in findings:
            self._apply_rules(finding, NIS2_MAPPINGS, ComplianceStandard.NIS2)
            self._apply_rules(finding, DORA_MAPPINGS, ComplianceStandard.DORA)

    def _apply_rules(
        self,
        finding: TechnicalFinding,
        mapping: dict,
        standard: ComplianceStandard
    ):
        """Apply compliance rules to a finding."""
        for key, rule in mapping.items():
            if key in finding.title or key in finding.description:
                violation = Violation(
                    standard=standard,
                    article=rule["article"],
                    description=rule["description"],
                    remediation_suggestion=f"Address '{finding.title}' to comply with {standard.value} {rule['article']}."
                )
                finding.compliance_violations.append(violation)
