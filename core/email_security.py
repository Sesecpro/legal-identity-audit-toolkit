"""
Sesecpro Compliance Engine - Email Security Analysis
=====================================================
Validates SPF, DKIM, and DMARC configurations.
Business Impact: Email authentication failures affect deliverability
and indicate potential spoofing vulnerabilities (NIS2 Art. 21).
"""
import asyncio
import dns.resolver
from typing import List, Dict, Optional
from .models import TechnicalFinding, RiskLevel


class EmailSecurityAnalyzer:
    """
    Analyzes email authentication records (SPF, DKIM, DMARC).
    """

    def __init__(self):
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = 5
        self.resolver.lifetime = 5

    async def analyze_email_security(self, domain: str) -> List[TechnicalFinding]:
        """Complete email security analysis."""
        findings = []

        # SPF Check
        spf_findings = await self._check_spf(domain)
        findings.extend(spf_findings)

        # DMARC Check
        dmarc_findings = await self._check_dmarc(domain)
        findings.extend(dmarc_findings)

        # DKIM (check common selectors)
        dkim_findings = await self._check_dkim(domain)
        findings.extend(dkim_findings)

        return findings

    async def _check_spf(self, domain: str) -> List[TechnicalFinding]:
        """Validate SPF record."""
        loop = asyncio.get_running_loop()
        findings = []

        try:
            txt_records = await loop.run_in_executor(
                None, lambda: self.resolver.resolve(domain, 'TXT')
            )
            spf_record = None
            for record in txt_records:
                txt = str(record).strip('"')
                if txt.startswith("v=spf1"):
                    spf_record = txt
                    break

            if not spf_record:
                findings.append(TechnicalFinding(
                    title="Missing SPF Record",
                    description=f"No SPF record found for {domain}. Email spoofing is possible.",
                    risk_level=RiskLevel.HIGH,
                    technical_details={"domain": domain}
                ))
            else:
                # Check SPF quality
                if "+all" in spf_record:
                    findings.append(TechnicalFinding(
                        title="Weak SPF Policy (+all)",
                        description=f"SPF uses '+all' which allows any sender. This defeats SPF purpose.",
                        risk_level=RiskLevel.HIGH,
                        technical_details={"spf": spf_record}
                    ))
                elif "~all" in spf_record:
                    findings.append(TechnicalFinding(
                        title="Soft-fail SPF Policy (~all)",
                        description=f"SPF uses soft-fail. Consider using '-all' for stricter enforcement.",
                        risk_level=RiskLevel.MEDIUM,
                        technical_details={"spf": spf_record}
                    ))
                elif "-all" in spf_record:
                    findings.append(TechnicalFinding(
                        title="Strong SPF Configuration",
                        description=f"SPF properly configured with hard-fail policy.",
                        risk_level=RiskLevel.INFO,
                        technical_details={"spf": spf_record}
                    ))

        except Exception:
            findings.append(TechnicalFinding(
                title="Missing SPF Record",
                description=f"No SPF record found for {domain}.",
                risk_level=RiskLevel.HIGH
            ))

        return findings

    async def _check_dmarc(self, domain: str) -> List[TechnicalFinding]:
        """Validate DMARC record."""
        loop = asyncio.get_running_loop()
        findings = []
        dmarc_domain = f"_dmarc.{domain}"

        try:
            txt_records = await loop.run_in_executor(
                None, lambda: self.resolver.resolve(dmarc_domain, 'TXT')
            )
            dmarc_record = None
            for record in txt_records:
                txt = str(record).strip('"')
                if txt.startswith("v=DMARC1"):
                    dmarc_record = txt
                    break

            if not dmarc_record:
                findings.append(TechnicalFinding(
                    title="Missing DMARC Record",
                    description=f"No DMARC policy for {domain}. Email spoofing protection incomplete.",
                    risk_level=RiskLevel.HIGH,
                    technical_details={"domain": domain}
                ))
            else:
                # Check DMARC policy
                if "p=none" in dmarc_record:
                    findings.append(TechnicalFinding(
                        title="DMARC Policy: None (Monitoring Only)",
                        description=f"DMARC is only monitoring. No emails are rejected.",
                        risk_level=RiskLevel.MEDIUM,
                        technical_details={"dmarc": dmarc_record}
                    ))
                elif "p=quarantine" in dmarc_record:
                    findings.append(TechnicalFinding(
                        title="DMARC Policy: Quarantine",
                        description=f"DMARC quarantines suspicious emails. Consider upgrading to reject.",
                        risk_level=RiskLevel.LOW,
                        technical_details={"dmarc": dmarc_record}
                    ))
                elif "p=reject" in dmarc_record:
                    findings.append(TechnicalFinding(
                        title="Strong DMARC Configuration",
                        description=f"DMARC properly configured with reject policy.",
                        risk_level=RiskLevel.INFO,
                        technical_details={"dmarc": dmarc_record}
                    ))

        except Exception:
            findings.append(TechnicalFinding(
                title="Missing DMARC Record",
                description=f"No DMARC policy for {domain}.",
                risk_level=RiskLevel.HIGH
            ))

        return findings

    async def _check_dkim(self, domain: str) -> List[TechnicalFinding]:
        """Check for DKIM selectors."""
        loop = asyncio.get_running_loop()
        findings = []

        # Common DKIM selectors
        selectors = ["default", "google", "selector1", "selector2", "k1", "dkim"]
        found_dkim = False

        for selector in selectors:
            dkim_domain = f"{selector}._domainkey.{domain}"
            try:
                await loop.run_in_executor(
                    None, lambda d=dkim_domain: self.resolver.resolve(d, 'TXT')
                )
                found_dkim = True
                findings.append(TechnicalFinding(
                    title="DKIM Configured",
                    description=f"DKIM selector '{selector}' found for {domain}.",
                    risk_level=RiskLevel.INFO,
                    technical_details={"selector": selector, "domain": domain}
                ))
                break
            except Exception:
                continue

        if not found_dkim:
            findings.append(TechnicalFinding(
                title="No DKIM Detected",
                description=f"No common DKIM selectors found for {domain}. Email signing may not be configured.",
                risk_level=RiskLevel.MEDIUM,
                technical_details={"domain": domain}
            ))

        return findings
