"""
Sesecpro Compliance Engine - Core Data Models
==============================================
Business Risk Context: These models represent the fundamental data structures
for asset inventory, security findings, and regulatory compliance mapping.
Each finding carries both technical severity and business impact indicators.
"""
from dataclasses import dataclass, field
from typing import List, Dict
from enum import Enum
from datetime import datetime


class RiskLevel(str, Enum):
    """
    Risk levels aligned with enterprise risk frameworks.
    CRITICAL/HIGH require immediate executive notification per NIS2 Art. 23.
    """
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class AssetType(str, Enum):
    """Asset classification for inventory management (DORA Art. 8)."""
    DOMAIN = "DOMAIN"
    SUBDOMAIN = "SUBDOMAIN"
    IP = "IP"
    MAIL_SERVER = "MAIL_SERVER"


class ComplianceStandard(str, Enum):
    """Supported regulatory frameworks."""
    NIS2 = "NIS2"
    DORA = "DORA"


@dataclass
class Violation:
    """
    Represents a specific regulatory non-compliance.
    Links technical findings to legal obligations.
    """
    standard: ComplianceStandard
    article: str
    description: str
    remediation_suggestion: str


@dataclass
class TechnicalFinding:
    """
    A security issue discovered during reconnaissance.
    Business Impact: Each finding may trigger regulatory reporting obligations.
    """
    title: str
    description: str
    risk_level: RiskLevel
    technical_details: Dict[str, str] = field(default_factory=dict)
    compliance_violations: List[Violation] = field(default_factory=list)
    timestamp: datetime = field(default_factory=datetime.now)


@dataclass
class Asset:
    """
    Represents a discovered digital asset.
    Shadow IT Detection: Assets marked as is_shadow_it=True indicate
    unmanaged infrastructure that poses supply chain risk (NIS2 Art. 21).
    """
    name: str
    asset_type: AssetType
    is_shadow_it: bool = False
    findings: List[TechnicalFinding] = field(default_factory=list)
    metadata: Dict[str, str] = field(default_factory=dict)


@dataclass
class ScanResult:
    """
    Complete scan output for a target domain.
    Designed for integration with Sesecpro TrustLink portal.
    """
    target_domain: str
    scan_date: datetime = field(default_factory=datetime.now)
    assets: List[Asset] = field(default_factory=list)
    compliance_score: float = 0.0
