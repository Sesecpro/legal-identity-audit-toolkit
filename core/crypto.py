"""
Sesecpro Compliance Engine - SSL/TLS Analysis Module
=====================================================
Cryptographic Posture: Verifies cipher strength against 2026 banking standards.
Business Impact: Weak encryption exposes the organization to data breaches
and regulatory penalties under NIS2 Art. 21(2)(f).
"""
import asyncio
import ssl
import socket
from typing import List, Optional
from .models import TechnicalFinding, RiskLevel


class CryptoAnalyzer:
    """
    SSL/TLS configuration analyzer.
    Validates cryptographic settings against enterprise security standards.
    """

    # Weak ciphers that fail 2026 banking/legal standards
    WEAK_CIPHERS = ['RC4', 'DES', '3DES', 'MD5', 'NULL', 'EXPORT', 'anon']
    DEPRECATED_PROTOCOLS = ['SSLv2', 'SSLv3', 'TLSv1', 'TLSv1.1']

    async def analyze_ssl_config(self, hostname: str, port: int = 443) -> List[TechnicalFinding]:
        """Analyze SSL/TLS configuration of a host."""
        findings = []
        loop = asyncio.get_running_loop()

        try:
            cipher_info = await loop.run_in_executor(
                None, self._get_cipher_info, hostname, port
            )

            if not cipher_info:
                findings.append(TechnicalFinding(
                    title="SSL Connection Failed",
                    description=f"Could not establish SSL connection to {hostname}:{port}",
                    risk_level=RiskLevel.MEDIUM
                ))
                return findings

            protocol_version = cipher_info['version']
            cipher_name = cipher_info['cipher']

            # Check Protocol Version
            if protocol_version in self.DEPRECATED_PROTOCOLS:
                findings.append(TechnicalFinding(
                    title=f"Deprecated SSL/TLS Protocol: {protocol_version}",
                    description=f"Server supports {protocol_version}, which is deprecated. Must upgrade to TLS 1.2+.",
                    risk_level=RiskLevel.CRITICAL,
                    technical_details={"protocol": protocol_version, "hostname": hostname}
                ))

            # Check Cipher Strength
            if any(weak in cipher_name.upper() for weak in self.WEAK_CIPHERS):
                findings.append(TechnicalFinding(
                    title=f"Weak Cipher Suite: {cipher_name}",
                    description=f"The cipher suite {cipher_name} is considered weak.",
                    risk_level=RiskLevel.HIGH,
                    technical_details={"cipher": cipher_name, "hostname": hostname}
                ))

            # If TLS 1.3, add positive finding
            if protocol_version == 'TLSv1.3':
                findings.append(TechnicalFinding(
                    title="Strong TLS Configuration",
                    description=f"{hostname} uses TLS 1.3 with {cipher_name}",
                    risk_level=RiskLevel.INFO,
                    technical_details={"protocol": protocol_version, "cipher": cipher_name}
                ))

        except Exception as e:
            findings.append(TechnicalFinding(
                title="SSL Analysis Error",
                description=f"Error analyzing SSL for {hostname}: {str(e)}",
                risk_level=RiskLevel.LOW
            ))

        return findings

    def _get_cipher_info(self, hostname: str, port: int) -> Optional[dict]:
        """Get cipher and protocol information from SSL handshake."""
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        try:
            with socket.create_connection((hostname, port), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    return {
                        'cipher': ssock.cipher()[0],
                        'version': ssock.version()
                    }
        except Exception:
            return None
