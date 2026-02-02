#!/usr/bin/env python3
"""
Sesecpro Compliance Engine v2.0
================================
Enterprise reconnaissance and NIS2/DORA compliance assessment tool.

(c) 2026 Sesecpro - Consultoria de Ciberseguridad Enterprise
"""
import asyncio
import sys
import argparse
import logging
import warnings
from rich.live import Live
from rich.console import Console
from rich.panel import Panel
from rich.text import Text

from core.models import ScanResult, AssetType, Asset
from core.discovery import DiscoveryEngine
from core.ct_scanner import CTLogScanner
from core.network import NetworkAnalyzer
from core.crypto import CryptoAnalyzer
from core.email_security import EmailSecurityAnalyzer
from core.http_security import HTTPSecurityAnalyzer
from compliance.engine import ComplianceEngine
from compliance.scoring import ComplianceScorer
from ui.dashboard import ComplianceDashboard
from utils.export import TrustLinkExporter
from utils.pdf_report import PDFReportGenerator

# Suppress SSL warnings for header analysis
warnings.filterwarnings('ignore', message='Unverified HTTPS request')

# Configure logging
logging.basicConfig(
    level=logging.WARNING,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('sesecpro')


async def main():
    """Main entry point for the Sesecpro Compliance Engine."""
    parser = argparse.ArgumentParser(
        description="Sesecpro Compliance Engine v2.0 - Enterprise NIS2/DORA Assessment"
    )
    parser.add_argument("domain", help="Target domain to scan")
    parser.add_argument("--output", help="Output JSON file", default="report.json")
    parser.add_argument("--pdf", help="Generate PDF report", action="store_true")
    parser.add_argument("--ct", help="Include CT log discovery", action="store_true", default=True)
    args = parser.parse_args()

    target = args.domain
    console = Console()

    # Header
    console.print(Panel(
        Text("SESECPRO COMPLIANCE ENGINE v2.0", style="bold white", justify="center"),
        style="blue"
    ))
    console.print(f"[dim]Target: {target}[/]\n")

    # Initialize modules
    discovery = DiscoveryEngine(target)
    ct_scanner = CTLogScanner(target)
    network = NetworkAnalyzer()
    crypto = CryptoAnalyzer()
    email_analyzer = EmailSecurityAnalyzer()
    http_analyzer = HTTPSecurityAnalyzer()
    compliance_engine = ComplianceEngine()
    scorer = ComplianceScorer()
    dashboard = ComplianceDashboard()
    exporter = TrustLinkExporter()

    scan_result = ScanResult(target_domain=target)

    try:
        with Live(dashboard.render_layout([], "Initializing...", 0), refresh_per_second=4) as live:

            # Phase 1: Discovery (Brute-force + CT Logs)
            live.update(dashboard.render_layout([], "Phase 1: Discovering Assets...", 0.05))

            # Brute-force discovery
            assets = await discovery.scan_subdomains()

            # CT Log discovery
            if args.ct:
                live.update(dashboard.render_layout(assets, "Querying Certificate Transparency logs...", 0.1))
                ct_subdomains = await ct_scanner.scan_ct_logs()
                existing_names = {a.name for a in assets}
                for name in ct_subdomains:
                    if name not in existing_names:
                        # Check if it resolves
                        if await discovery._resolve_dns(name):
                            shadow_indicators = ['dev', 'test', 'staging', 'legacy', 'old', 'demo']
                            is_shadow = any(k in name for k in shadow_indicators)
                            assets.append(Asset(
                                name=name,
                                asset_type=AssetType.SUBDOMAIN,
                                is_shadow_it=is_shadow,
                                metadata={"dns_resolves": "true", "source": "CT_LOG"}
                            ))

            scan_result.assets = assets
            live.update(dashboard.render_layout(assets, f"Discovered {len(assets)} assets", 0.15))

            # Phase 2: Email Security (SPF/DKIM/DMARC) - Only on root domain
            live.update(dashboard.render_layout(assets, "Phase 2: Analyzing Email Security...", 0.2))
            email_findings = await email_analyzer.analyze_email_security(target)
            # Add to root domain asset
            for asset in assets:
                if asset.asset_type == AssetType.DOMAIN:
                    asset.findings.extend(email_findings)
                    break
            else:
                # If no domain asset, add one
                domain_asset = Asset(
                    name=target,
                    asset_type=AssetType.DOMAIN,
                    is_shadow_it=False,
                    findings=email_findings
                )
                assets.append(domain_asset)

            # Phase 3: Network, Crypto & HTTP Analysis
            total_assets = len(assets) or 1
            for i, asset in enumerate(assets):
                progress = 0.25 + ((i / total_assets) * 0.5)
                live.update(dashboard.render_layout(assets, f"Phase 3: Scanning {asset.name}...", progress))

                # MX & RBL checks (skip for subdomains, already in email analysis)
                if asset.asset_type == AssetType.DOMAIN:
                    mx_findings = await network.analyze_mx_records(asset.name)
                    asset.findings.extend(mx_findings)

                # SSL/TLS checks
                if asset.metadata.get("dns_resolves") == "true" or asset.asset_type == AssetType.DOMAIN:
                    ssl_findings = await crypto.analyze_ssl_config(asset.name)
                    asset.findings.extend(ssl_findings)

                    # HTTP Security Headers
                    http_findings = await http_analyzer.analyze_headers(asset.name)
                    asset.findings.extend(http_findings)

            # Phase 4: Compliance Mapping
            live.update(dashboard.render_layout(assets, "Phase 4: Mapping to NIS2/DORA Standards...", 0.85))
            for asset in assets:
                compliance_engine.evaluate_findings(asset.findings)

            # Phase 5: Scoring
            live.update(dashboard.render_layout(assets, "Phase 5: Calculating Compliance Score...", 0.95))
            compliance_score = scorer.calculate_score(scan_result)
            scan_result.compliance_score = compliance_score

            # Finalize
            live.update(dashboard.render_layout(assets, "Scan Complete!", 1.0))
            await asyncio.sleep(0.5)

        # Export JSON
        exporter.export(scan_result, args.output)

        # Generate PDF if requested
        pdf_file = None
        if args.pdf:
            pdf_file = args.output.replace('.json', '.pdf')
            pdf_generator = PDFReportGenerator(scan_result, compliance_score)
            pdf_generator.generate(pdf_file)

        # Summary
        console.print()
        score_color = scorer.get_score_color(compliance_score)
        grade = scorer.get_score_grade(compliance_score)
        console.print(Panel(
            f"[bold]Compliance Score: [{score_color}]{compliance_score}/100 (Grade: {grade})[/{score_color}][/]",
            title="Assessment Complete",
            style="green"
        ))
        console.print(f"[dim]JSON Report: {args.output}[/]")
        if pdf_file:
            console.print(f"[dim]PDF Report: {pdf_file}[/]")
        console.print()

    except KeyboardInterrupt:
        console.print("\n[yellow]Scan interrupted by user.[/]")
        sys.exit(1)
    except Exception as e:
        logger.exception("Scan failed")
        console.print(f"\n[bold red]Error: {e}[/]")
        sys.exit(1)


if __name__ == "__main__":
    if sys.platform == 'win32':
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    asyncio.run(main())
