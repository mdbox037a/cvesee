from pydantic import BaseModel, Field
from dataclasses import dataclass
from datetime import datetime
from typing import List, Any, Optional


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


class CVSS40Metric(BaseModel):
    # bookmark
    pass


class NVDMetrics(BaseModel):
    cvss_v40: Optional[List[CVSS40Metric]] = Field(None, alias="cvssMetricV40")
    cvss_v31: Optional[List[CVSS31Metric]] = Field(None, alias="cvssMetricV31")
    cvss_v30: Optional[List[CVSS30Metric]] = Field(None, alias="cvssMetricV30")
    cvss_v2: Optional[List[CVSS2Metric]] = Field(None, alias="cvssMetricV2")


class NVDCVEInfo(BaseModel):
    id: str
    cna: str = Field(alias="sourceIdentifier")
    date_published: datetime = Field(alias="published")
    date_last_modified: datetime = Field(alias="lastModified")
    metrics: Optional[NVDMetrics] = None


class NVDCVEWrapper(BaseModel):
    cve: NVDCVEInfo


class NVDAPIFull(BaseModel):
    accessed: str = Field(alias="timestamp")
    vulnerabilities: List[NVDCVEWrapper]
