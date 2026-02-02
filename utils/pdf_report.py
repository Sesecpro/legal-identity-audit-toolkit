"""
Sesecpro Compliance Engine - PDF Report Generator
==================================================
Generates executive-ready PDF reports with Sesecpro branding.
"""
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import cm
from reportlab.lib.colors import HexColor, black, white
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, 
    PageBreak, Image
)
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from datetime import datetime
from core.models import ScanResult, RiskLevel


class PDFReportGenerator:
    """
    Generates professional PDF reports for Sesecpro clients.
    """

    # Sesecpro brand colors
    PRIMARY_COLOR = HexColor("#1a365d")  # Dark blue
    ACCENT_COLOR = HexColor("#3182ce")   # Light blue
    DANGER_COLOR = HexColor("#e53e3e")   # Red
    WARNING_COLOR = HexColor("#dd6b20")  # Orange
    SUCCESS_COLOR = HexColor("#38a169")  # Green

    def __init__(self, scan_result: ScanResult, compliance_score: float):
        self.scan_result = scan_result
        self.compliance_score = compliance_score
        self.styles = getSampleStyleSheet()
        self._setup_custom_styles()

    def _setup_custom_styles(self):
        """Setup custom paragraph styles."""
        self.styles.add(ParagraphStyle(
            name='ReportTitle',
            parent=self.styles['Heading1'],
            fontSize=24,
            textColor=self.PRIMARY_COLOR,
            spaceAfter=30,
            alignment=TA_CENTER
        ))
        self.styles.add(ParagraphStyle(
            name='SectionHeader',
            parent=self.styles['Heading2'],
            fontSize=16,
            textColor=self.PRIMARY_COLOR,
            spaceBefore=20,
            spaceAfter=10
        ))
        self.styles.add(ParagraphStyle(
            name='FindingTitle',
            parent=self.styles['Normal'],
            fontSize=11,
            textColor=black,
            fontName='Helvetica-Bold'
        ))

    def generate(self, filename: str):
        """Generate the PDF report."""
        doc = SimpleDocTemplate(
            filename,
            pagesize=A4,
            rightMargin=2*cm,
            leftMargin=2*cm,
            topMargin=2*cm,
            bottomMargin=2*cm
        )

        story = []

        # Title
        story.append(Paragraph(
            "Informe de Cumplimiento NIS2/DORA",
            self.styles['ReportTitle']
        ))
        story.append(Paragraph(
            f"Dominio: {self.scan_result.target_domain}",
            self.styles['Normal']
        ))
        story.append(Paragraph(
            f"Fecha: {datetime.now().strftime('%d/%m/%Y %H:%M')}",
            self.styles['Normal']
        ))
        story.append(Spacer(1, 20))

        # Executive Summary
        story.append(Paragraph("Resumen Ejecutivo", self.styles['SectionHeader']))

        # Score display
        score_color = self._get_score_color()
        story.append(Paragraph(
            f"<b>Puntuación de Cumplimiento:</b> <font color='{score_color}'>{self.compliance_score}/100</font>",
            self.styles['Normal']
        ))
        story.append(Spacer(1, 10))

        # Asset summary
        total_assets = len(self.scan_result.assets)
        shadow_it_count = sum(1 for a in self.scan_result.assets if a.is_shadow_it)
        story.append(Paragraph(
            f"<b>Activos Descubiertos:</b> {total_assets}",
            self.styles['Normal']
        ))
        if shadow_it_count > 0:
            story.append(Paragraph(
                f"<b>Shadow IT Detectado:</b> <font color='red'>{shadow_it_count} activos</font>",
                self.styles['Normal']
            ))
        story.append(Spacer(1, 20))

        # Findings summary table
        story.append(Paragraph("Resumen de Hallazgos", self.styles['SectionHeader']))

        findings_by_severity = self._count_findings_by_severity()
        table_data = [
            ["Severidad", "Cantidad"],
            ["CRITICAL", str(findings_by_severity.get(RiskLevel.CRITICAL, 0))],
            ["HIGH", str(findings_by_severity.get(RiskLevel.HIGH, 0))],
            ["MEDIUM", str(findings_by_severity.get(RiskLevel.MEDIUM, 0))],
            ["LOW", str(findings_by_severity.get(RiskLevel.LOW, 0))],
            ["INFO", str(findings_by_severity.get(RiskLevel.INFO, 0))]
        ]

        table = Table(table_data, colWidths=[8*cm, 4*cm])
        table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), self.PRIMARY_COLOR),
            ('TEXTCOLOR', (0, 0), (-1, 0), white),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 12),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, 1), HexColor("#fed7d7")),  # Critical row
            ('BACKGROUND', (0, 2), (-1, 2), HexColor("#feebc8")),  # High row
            ('GRID', (0, 0), (-1, -1), 1, black)
        ]))
        story.append(table)
        story.append(Spacer(1, 20))

        # Detailed Findings
        story.append(PageBreak())
        story.append(Paragraph("Hallazgos Detallados", self.styles['SectionHeader']))

        for asset in self.scan_result.assets:
            if asset.findings:
                story.append(Paragraph(
                    f"<b>{asset.name}</b> ({asset.asset_type.value})",
                    self.styles['FindingTitle']
                ))
                for finding in asset.findings:
                    color = self._get_finding_color(finding.risk_level)
                    story.append(Paragraph(
                        f"• <font color='{color}'>[{finding.risk_level.value}]</font> {finding.title}",
                        self.styles['Normal']
                    ))
                    story.append(Paragraph(
                        f"  <i>{finding.description}</i>",
                        self.styles['Normal']
                    ))
                    if finding.compliance_violations:
                        for v in finding.compliance_violations:
                            story.append(Paragraph(
                                f"  → <b>{v.standard.value} {v.article}</b>: {v.description}",
                                self.styles['Normal']
                            ))
                    story.append(Spacer(1, 5))
                story.append(Spacer(1, 15))

        # Footer
        story.append(Spacer(1, 30))
        story.append(Paragraph(
            "─" * 50,
            self.styles['Normal']
        ))
        story.append(Paragraph(
            "<i>Generado por Sesecpro Compliance Engine</i>",
            ParagraphStyle(name='Footer', alignment=TA_CENTER, textColor=HexColor("#666666"))
        ))

        doc.build(story)

    def _count_findings_by_severity(self):
        """Count findings by severity level."""
        counts = {}
        for asset in self.scan_result.assets:
            for finding in asset.findings:
                counts[finding.risk_level] = counts.get(finding.risk_level, 0) + 1
        return counts

    def _get_score_color(self):
        """Get color for score."""
        if self.compliance_score >= 80:
            return "green"
        elif self.compliance_score >= 60:
            return "orange"
        else:
            return "red"

    def _get_finding_color(self, risk_level: RiskLevel):
        """Get color for finding severity."""
        colors = {
            RiskLevel.CRITICAL: "red",
            RiskLevel.HIGH: "red",
            RiskLevel.MEDIUM: "orange",
            RiskLevel.LOW: "blue",
            RiskLevel.INFO: "green"
        }
        return colors.get(risk_level, "black")
