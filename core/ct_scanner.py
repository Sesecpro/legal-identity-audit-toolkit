"""
Sesecpro Compliance Engine - Certificate Transparency Discovery
================================================================
Integrates with crt.sh to discover subdomains from CT logs.
This provides real-world subdomain intelligence beyond brute-force.
"""
import asyncio
import requests
from typing import List, Set


class CTLogScanner:
    """
    Certificate Transparency Log scanner using crt.sh.
    Business Context: CT logs reveal all SSL certificates ever issued,
    exposing forgotten/shadow assets that may pose compliance risks.
    """

    CRT_SH_URL = "https://crt.sh/?q={}&output=json"

    def __init__(self, target_domain: str):
        self.target_domain = target_domain
        self.discovered_names: Set[str] = set()

    async def scan_ct_logs(self) -> List[str]:
        """
        Query crt.sh for certificate transparency records.
        Returns list of unique subdomain names.
        """
        loop = asyncio.get_running_loop()
        try:
            subdomains = await loop.run_in_executor(None, self._fetch_ct_records)
            return list(subdomains)
        except Exception:
            return []

    def _fetch_ct_records(self) -> Set[str]:
        """Synchronous fetch from crt.sh API."""
        try:
            url = self.CRT_SH_URL.format(f"%.{self.target_domain}")
            response = requests.get(url, timeout=15)
            if response.status_code != 200:
                return set()

            data = response.json()
            names = set()
            for entry in data:
                name_value = entry.get("name_value", "")
                # CT logs can have wildcards and multiple names
                for name in name_value.split("\n"):
                    name = name.strip().lower()
                    if name.startswith("*."):
                        name = name[2:]
                    if name.endswith(self.target_domain) and name:
                        names.add(name)

            return names
        except Exception:
            return set()
