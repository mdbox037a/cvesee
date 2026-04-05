from dataclasses import dataclass
from typing import Optional


@dataclass
class NVDInfo:
    """child class for info specific to NVD"""

    url: str
    published_date: Optional[str] = None
    last_updated_date: Optional[str] = None
    nist_score: float = 0.0
    nist_severity: str
    cna_score: float = 0.0
    cna_severity: str
    patches: list


@dataclass
class CVE:
    """parent class to hold all parsed information"""

    cve_id: str
    description: str
    nvd: NVDInfo
