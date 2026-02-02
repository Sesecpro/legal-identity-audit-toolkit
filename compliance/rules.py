"""
Sesecpro Compliance Engine - Compliance Rules
==============================================
Regulatory Mapping: Links technical vulnerabilities to specific NIS2/DORA articles.
Extended with email security and HTTP header mappings.
"""
from core.models import ComplianceStandard

# NIS2 Directive Article Mappings
NIS2_MAPPINGS = {
    # Asset Management
    "Shadow IT": {
        "article": "Article 21(2)(d)",
        "description": "Supply chain security and asset management. Unmanaged assets pose risk to network security."
    },
    # Cryptography
    "Deprecated SSL/TLS": {
        "article": "Article 21(2)(f)",
        "description": "Basic cyber hygiene and cryptography. Outdated encryption fails confidentiality requirements."
    },
    "Weak Cipher": {
        "article": "Article 21(2)(f)",
        "description": "Cryptography standards. Weak ciphers do not provide adequate protection."
    },
    # Email Security
    "Missing SPF": {
        "article": "Article 21(2)(f)",
        "description": "Basic cyber hygiene. SPF prevents email spoofing attacks."
    },
    "Weak SPF": {
        "article": "Article 21(2)(f)",
        "description": "Email authentication policy is too permissive."
    },
    "Missing DMARC": {
        "article": "Article 21(2)(f)",
        "description": "DMARC policy required for email authentication."
    },
    "DMARC Policy: None": {
        "article": "Article 21(2)(f)",
        "description": "DMARC monitoring-only mode does not prevent spoofing."
    },
    # Business Continuity
    "Missing MX": {
        "article": "Article 21(2)(c)",
        "description": "Business continuity management. Core communication infrastructure must be maintained."
    },
    # Reputation
    "Blacklisted": {
        "article": "Article 21(2)(d)",
        "description": "Network security. Compromised reputation indicates potential breach or abuse."
    },
    # HTTP Security
    "Missing Security Header": {
        "article": "Article 21(2)(f)",
        "description": "Basic cyber hygiene. Security headers prevent common web attacks."
    }
}

# DORA Regulation Article Mappings
DORA_MAPPINGS = {
    # Asset Management
    "Shadow IT": {
        "article": "Article 8",
        "description": "ICT asset identification. All assets must be inventoried and managed."
    },
    # Cryptography
    "Deprecated SSL/TLS": {
        "article": "Article 9(2)",
        "description": "Protection and prevention. Encryption protocols must be reviewed regularly."
    },
    "Weak Cipher": {
        "article": "Article 9(1)",
        "description": "Information security policy. State-of-the-art cryptography required."
    },
    # Email Security
    "Missing SPF": {
        "article": "Article 9(3)",
        "description": "ICT security policies must address email authentication."
    },
    "Weak SPF": {
        "article": "Article 9(3)",
        "description": "Email authentication controls must be effective."
    },
    "Missing DMARC": {
        "article": "Article 9(3)",
        "description": "Email security policies incomplete without DMARC."
    },
    "DMARC Policy: None": {
        "article": "Article 9(3)",
        "description": "DMARC enforcement required to prevent fraud."
    },
    # Business Continuity
    "Missing MX": {
        "article": "Article 11",
        "description": "Response and recovery. Critical communication channels must be available."
    },
    # Reputation
    "Blacklisted": {
        "article": "Article 9",
        "description": "Protection and prevention. Detection of anomalous activities affecting ICT services."
    },
    # HTTP Security
    "Missing Security Header": {
        "article": "Article 9(2)",
        "description": "Web application security controls required."
    }
}
