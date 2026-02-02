"""
Sesecpro Compliance Engine - HTTP Security Headers Analysis
============================================================
Validates security headers against best practices.
Business Impact: Missing headers indicate basic hygiene failures (NIS2 Art. 21(2)(f)).
"""
import asyncio
import requests
from typing import List, Dict
from .models import TechnicalFinding, RiskLevel


class HTTPSecurityAnalyzer:
    """
    Analyzes HTTP security headers.
    """

    # Required security headers and their importance
    SECURITY_HEADERS = {
        "Strict-Transport-Security": {
            "description": "HSTS - Forces HTTPS connections",
            "missing_risk": RiskLevel.HIGH
        },
        "Content-Security-Policy": {
            "description": "CSP - Prevents XSS and injection attacks",
            "missing_risk": RiskLevel.HIGH
        },
        "X-Frame-Options": {
            "description": "Prevents clickjacking attacks",
            "missing_risk": RiskLevel.MEDIUM
        },
        "X-Content-Type-Options": {
            "description": "Prevents MIME type sniffing",
            "missing_risk": RiskLevel.MEDIUM
        },
        "X-XSS-Protection": {
            "description": "Legacy XSS filter (deprecated but still checked)",
            "missing_risk": RiskLevel.LOW
        },
        "Referrer-Policy": {
            "description": "Controls referrer information leakage",
            "missing_risk": RiskLevel.LOW
        },
        "Permissions-Policy": {
            "description": "Controls browser feature permissions",
            "missing_risk": RiskLevel.LOW
        }
    }

    async def analyze_headers(self, hostname: str) -> List[TechnicalFinding]:
        """Analyze HTTP security headers for a host."""
        loop = asyncio.get_running_loop()
        findings = []

        try:
            headers = await loop.run_in_executor(None, self._fetch_headers, hostname)
            if headers is None:
                findings.append(TechnicalFinding(
                    title="HTTP Connection Failed",
                    description=f"Could not connect to {hostname} for header analysis.",
                    risk_level=RiskLevel.MEDIUM
                ))
                return findings

            # Check each security header
            present_headers = []
            missing_headers = []

            for header_name, config in self.SECURITY_HEADERS.items():
                if header_name.lower() in [h.lower() for h in headers.keys()]:
                    present_headers.append(header_name)
                else:
                    missing_headers.append((header_name, config))

            # Report missing headers
            for header_name, config in missing_headers:
                findings.append(TechnicalFinding(
                    title=f"Missing Security Header: {header_name}",
                    description=f"{config['description']}. This header is not set on {hostname}.",
                    risk_level=config["missing_risk"],
                    technical_details={"header": header_name, "hostname": hostname}
                ))

            # Summary of present headers
            if present_headers:
                findings.append(TechnicalFinding(
                    title="Security Headers Present",
                    description=f"{len(present_headers)} of {len(self.SECURITY_HEADERS)} security headers configured.",
                    risk_level=RiskLevel.INFO,
                    technical_details={"headers": ", ".join(present_headers)}
                ))

        except Exception as e:
            findings.append(TechnicalFinding(
                title="Header Analysis Error",
                description=f"Error analyzing headers for {hostname}: {str(e)}",
                risk_level=RiskLevel.LOW
            ))

        return findings

    def _fetch_headers(self, hostname: str) -> Dict[str, str]:
        """Fetch HTTP headers from a host using GET with browser User-Agent.
        Note: Cloudflare/Vercel may filter security headers based on User-Agent.
        """
        browser_ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/121.0.0.0 Safari/537.36"
        try:
            url = f"https://{hostname}"
            response = requests.get(
                url, 
                timeout=10, 
                allow_redirects=True, 
                verify=False,
                headers={"User-Agent": browser_ua}
            )
            return dict(response.headers)
        except Exception:
            try:
                url = f"http://{hostname}"
                response = requests.get(
                    url, 
                    timeout=10, 
                    allow_redirects=True,
                    headers={"User-Agent": browser_ua}
                )
                return dict(response.headers)
            except Exception:
                return None
