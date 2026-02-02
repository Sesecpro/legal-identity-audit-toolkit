"""
Sesecpro Compliance Engine - JSON Export
=========================================
TrustLink Integration: Exports scan results in structured JSON format.
"""
import json
import dataclasses
from datetime import datetime
from enum import Enum
from core.models import ScanResult


class EnhancedJSONEncoder(json.JSONEncoder):
    """Custom JSON encoder for dataclasses and enums."""
    def default(self, o):
        if dataclasses.is_dataclass(o):
            return dataclasses.asdict(o)
        if isinstance(o, datetime):
            return o.isoformat()
        if isinstance(o, Enum):
            return o.value
        return super().default(o)


class TrustLinkExporter:
    """
    Exports scan results to JSON format compatible with Sesecpro TrustLink portal.
    """

    @staticmethod
    def export(scan_result: ScanResult, filename: str = "trustlink_export.json"):
        """Export ScanResult to JSON file."""
        export_data = {
            "version": "1.0",
            "source": "Sesecpro Compliance Engine",
            "generated_at": datetime.now().isoformat(),
            "payload": scan_result
        }

        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(export_data, f, indent=4, cls=EnhancedJSONEncoder, ensure_ascii=False)
