"""
Sesecpro Compliance Engine - Asset Discovery Module
====================================================
Shadow IT Detection: This module identifies digital assets that may exist
outside the organization's official inventory, representing unmanaged risk.
"""
import asyncio
import dns.resolver
from typing import List, Set
from .models import Asset, AssetType


class DiscoveryEngine:
    """
    Asynchronous subdomain discovery engine.
    Business Context: Unmapped assets represent supply chain vulnerabilities
    and potential NIS2 Art. 21 violations.
    """

    def __init__(self, target_domain: str):
        self.target_domain = target_domain
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = 3
        self.resolver.lifetime = 3
        self.found_subdomains: Set[str] = set()

    async def _resolve_dns(self, hostname: str) -> bool:
        """Checks if a hostname resolves to an IP address."""
        loop = asyncio.get_running_loop()
        try:
            await loop.run_in_executor(None, self.resolver.resolve, hostname, 'A')
            return True
        except Exception:
            return False

    async def scan_subdomains(self) -> List[Asset]:
        """
        Discovers subdomains using common prefix enumeration.
        In production, this would integrate with CT logs and passive DNS.
        """
        # Common subdomains that often indicate Shadow IT exposure
        common_prefixes = [
            "www", "mail", "remote", "blog", "dev", "test", "staging",
            "vpn", "jira", "wiki", "api", "portal", "legacy", "old",
            "admin", "ftp", "webmail", "owa", "autodiscover"
        ]

        tasks = []
        for prefix in common_prefixes:
            hostname = f"{prefix}.{self.target_domain}"
            tasks.append(self._check_subdomain(hostname))

        results = await asyncio.gather(*tasks)
        assets = [r for r in results if r is not None]

        # Add the root domain
        root_resolves = await self._resolve_dns(self.target_domain)
        if root_resolves:
            assets.append(Asset(
                name=self.target_domain,
                asset_type=AssetType.DOMAIN,
                is_shadow_it=False
            ))

        return assets

    async def _check_subdomain(self, hostname: str) -> Asset:
        """Check individual subdomain and classify Shadow IT probability."""
        resolves = await self._resolve_dns(hostname)
        if resolves:
            # Heuristic: dev/test/staging/legacy often indicate Shadow IT
            shadow_indicators = ['dev', 'test', 'staging', 'legacy', 'old', 'demo']
            is_shadow = any(k in hostname for k in shadow_indicators)
            return Asset(
                name=hostname,
                asset_type=AssetType.SUBDOMAIN,
                is_shadow_it=is_shadow,
                metadata={"dns_resolves": "true"}
            )
        return None
