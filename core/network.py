"""
Sesecpro Compliance Engine - Network Analysis Module
=====================================================
Email Security & Reputation: Analyzes MX records and checks against RBLs.
Business Impact: Blacklisted mail servers affect institutional deliverability.
"""
import asyncio
import dns.resolver
from typing import List
from .models import TechnicalFinding, RiskLevel


class NetworkAnalyzer:
    """
    Network configuration analyzer focusing on email infrastructure.
    Business Context: Email reputation directly impacts business communications.
    """

    def __init__(self):
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = 3
        self.resolver.lifetime = 3
        # Common RBLs (Real-time Blackhole Lists)
        self.rbls = [
            "zen.spamhaus.org",
            "b.barracudacentral.org",
            "bl.spamcop.net"
        ]

    async def analyze_mx_records(self, domain: str) -> List[TechnicalFinding]:
        """Analyze MX records and check mail server reputation."""
        loop = asyncio.get_running_loop()
        findings = []

        try:
            mx_records = await loop.run_in_executor(
                None, lambda: self.resolver.resolve(domain, 'MX')
            )
            for mx in mx_records:
                mx_host = str(mx.exchange).rstrip('.')
                try:
                    a_records = await loop.run_in_executor(
                        None, lambda h=mx_host: self.resolver.resolve(h, 'A')
                    )
                    for a in a_records:
                        ip = str(a)
                        rbl_findings = await self.check_rbl(ip, mx_host)
                        findings.extend(rbl_findings)
                except Exception:
                    pass

            return findings

        except dns.resolver.NXDOMAIN:
            findings.append(TechnicalFinding(
                title="Missing MX Records",
                description=f"No MX records found for {domain}. Email delivery will fail.",
                risk_level=RiskLevel.MEDIUM
            ))
            return findings
        except Exception as e:
            findings.append(TechnicalFinding(
                title="DNS Error Checking MX",
                description=f"Could not retrieve MX records for {domain}: {str(e)}",
                risk_level=RiskLevel.LOW
            ))
            return findings

    async def check_rbl(self, ip: str, hostname: str) -> List[TechnicalFinding]:
        """Check IP against Real-time Blackhole Lists."""
        reversed_ip = ".".join(reversed(ip.split(".")))
        findings = []
        loop = asyncio.get_running_loop()

        async def query_rbl(rbl):
            query_str = f"{reversed_ip}.{rbl}"
            try:
                await loop.run_in_executor(
                    None, lambda: self.resolver.resolve(query_str, 'A')
                )
                return rbl
            except Exception:
                return None

        tasks = [query_rbl(rbl) for rbl in self.rbls]
        results = await asyncio.gather(*tasks)

        for rbl in results:
            if rbl:
                findings.append(TechnicalFinding(
                    title="Mail Server Blacklisted",
                    description=f"Mail server {hostname} ({ip}) is listed on {rbl}.",
                    risk_level=RiskLevel.HIGH,
                    technical_details={"rbl": rbl, "ip": ip, "hostname": hostname}
                ))

        return findings
