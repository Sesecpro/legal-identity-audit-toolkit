# Legal Identity Audit Toolkit

**Sesecpro Compliance Engine v2.0** - Enterprise reconnaissance and NIS2/DORA compliance assessment tool.

![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)
![License](https://img.shields.io/badge/license-Proprietary-red.svg)

## Features

| Module | Description |
|--------|-------------|
| **Asset Discovery** | Subdomain enumeration + Certificate Transparency (crt.sh) |
| **Email Security** | SPF, DKIM, DMARC validation |
| **TLS Analysis** | Protocol version and cipher suite checks |
| **HTTP Headers** | HSTS, CSP, X-Frame-Options, etc. |
| **Compliance Mapping** | NIS2 Directive & DORA Regulation |
| **Scoring** | Weighted 0-100 compliance score |
| **Reports** | JSON (TrustLink compatible) + Executive PDF |

## Quick Start

```bash
# Clone
git clone https://github.com/Sesecpro/legal-identity-audit-toolkit.git
cd legal-identity-audit-toolkit

# Setup
python -m venv venv
.\venv\Scripts\activate  # Windows
pip install -r requirements.txt

# Run
python main.py example.com --output report.json --pdf
```

## Usage

```bash
# Basic scan
python main.py target.com --output target_report.json

# Full scan with PDF report
python main.py target.com --output target_report.json --pdf

# Disable CT log discovery
python main.py target.com --output target_report.json --no-ct
```

## Output Example

```json
{
  "version": "1.0",
  "source": "Sesecpro Compliance Engine",
  "payload": {
    "target_domain": "example.com",
    "compliance_score": 85.0,
    "assets": [...]
  }
}
```

## Architecture

```
├── main.py                    # Entry point
├── core/
│   ├── models.py             # Data models
│   ├── discovery.py          # Subdomain enumeration
│   ├── ct_scanner.py         # crt.sh integration
│   ├── network.py            # MX/RBL analysis
│   ├── crypto.py             # SSL/TLS analysis
│   ├── email_security.py     # SPF/DKIM/DMARC
│   └── http_security.py      # Security headers
├── compliance/
│   ├── rules.py              # NIS2/DORA mappings
│   ├── engine.py             # Violation evaluator
│   └── scoring.py            # Weighted scoring
├── ui/
│   └── dashboard.py          # Rich console UI
└── utils/
    ├── export.py             # JSON exporter
    └── pdf_report.py         # PDF generator
```

## Compliance Standards

- **NIS2 Directive** (EU 2022/2555) - Network and Information Security
- **DORA Regulation** (EU 2022/2554) - Digital Operational Resilience Act

## Requirements

- Python 3.10+
- See `requirements.txt`

## License

Proprietary - © 2026 Sesecpro

---

*Developed by Sesecpro - Consultoría de Ciberseguridad Enterprise*
