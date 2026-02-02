"""
Sesecpro Compliance Engine - Dashboard UI
==========================================
Professional console interface using Rich library.
"""
from rich.console import Console
from rich.layout import Layout
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich import box
from typing import List
from core.models import Asset, RiskLevel


class ComplianceDashboard:
    """
    Professional console dashboard for real-time scan visualization.
    """

    def __init__(self):
        self.console = Console()
        self.layout = Layout()
        self.layout.split(
            Layout(name="header", size=3),
            Layout(name="main", ratio=1),
            Layout(name="footer", size=3)
        )
        self.layout["main"].split_row(
            Layout(name="assets", ratio=1),
            Layout(name="findings", ratio=2)
        )
        self.header_text = Text(
            "  SESECPRO COMPLIANCE ENGINE - NIS2/DORA Readiness Assessment  ",
            style="bold white on blue",
            justify="center"
        )

    def render_layout(
        self,
        assets: List[Asset],
        processing_status: str,
        overall_progress: float
    ):
        """Render the dashboard layout."""
        self.layout["header"].update(Panel(self.header_text))

        # Assets Table
        asset_table = Table(box=box.SIMPLE_HEAD, expand=True)
        asset_table.add_column("Asset", style="cyan", no_wrap=True)
        asset_table.add_column("Type", style="magenta")
        asset_table.add_column("Shadow IT", style="red")

        for asset in assets[-10:]:
            shadow_mark = "[bold red]YES[/]" if asset.is_shadow_it else "[green]NO[/]"
            asset_table.add_row(asset.name, asset.asset_type.value, shadow_mark)

        self.layout["assets"].update(
            Panel(asset_table, title="[bold]Discovered Assets[/]", border_style="blue")
        )

        # Findings Panel
        findings_table = Table(box=box.SIMPLE, expand=True)
        findings_table.add_column("Severity", style="bold", width=10)
        findings_table.add_column("Finding", no_wrap=False)
        findings_table.add_column("Compliance", style="yellow", width=20)

        all_findings = []
        for asset in assets:
            for finding in asset.findings:
                all_findings.append(finding)

        for finding in all_findings[-10:]:
            violations = ", ".join([v.article for v in finding.compliance_violations])
            if finding.risk_level == RiskLevel.CRITICAL:
                color = "bold red"
            elif finding.risk_level == RiskLevel.HIGH:
                color = "red"
            elif finding.risk_level == RiskLevel.MEDIUM:
                color = "yellow"
            else:
                color = "green"

            findings_table.add_row(
                f"[{color}]{finding.risk_level.value}[/]",
                finding.title,
                violations if violations else "-"
            )

        self.layout["findings"].update(
            Panel(findings_table, title="[bold]Compliance Findings[/]", border_style="red")
        )

        # Footer
        progress_bar = "█" * int(overall_progress * 30) + "░" * (30 - int(overall_progress * 30))
        self.layout["footer"].update(
            Panel(
                Text(f"Status: {processing_status}  [{progress_bar}] {int(overall_progress*100)}%",
                     style="bold green"),
                border_style="green"
            )
        )

        return self.layout
