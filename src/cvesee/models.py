from pydantic import BaseModel, Field, model_validator, HttpUrl
from dataclasses import dataclass
from datetime import datetime
from typing import List, Any, Optional


class NVDInfo(BaseModel):
    cve_id: str
    base_score: Optional[float] = None
    severity: Optional[str] = None
    description: str
    reporting_cna: Optional[str] = None
    nist_cna: Optional[bool] = False
    nist_score: Optional[float] = None
    date_published: datetime
    date_last_modified: datetime
    date_accessed: datetime
    cve_tags: Optional[List[str]] = None
    vendor_advisories: Optional[List[HttpUrl]] = None
    patches: Optional[List[HttpUrl]] = None

    @model_validator(mode="before")
    @classmethod
    def flatten(cls, nvd_data: Any) -> Any:
        cve_wrapper = nvd_data.get("vulnerabilities", [{}]).get("cve", {})
        metrics_wrapper = cve_wrapper.get("metrics", {})
        # set cvss version preference order
        versions = [
            "cvssMetricV40",
            "cvssMetricV31",
            "cvssMetricV30",
            "cvssMetricV2",
        ]

        # get deeply nested data from 'mertics' wrapper
        for metric_version in versions:
            if metric_version in metrics_wrapper:
                cvss_data = metrics_wrapper[metric_version][0].get("cvssData", {})

                nvd_data["base_score"] = cvss_data.get("baseScore")
                nvd_data["severity"] = cvss_data.get("baseSeverity")

                # once we've captured one set of CVSS data, break
                break

        # get english language cve description
        descriptions = cve_wrapper.get("descriptions", [])
        for description in descriptions:
            if description["lang"] == "en":
                nvd_data["description"] = description["value"]

                # once we've captured the english string, break
                break

        # fill out the rest of the fields from the 'cve' wrapper
        nvd_data["cve_id"] = cve_wrapper.get("id")
        nvd_data["date_accessed"] = nvd_data["timestamp"]
        # bookmark


# heavy edits needed later
# define ultimate dataclass to hold all information from all sources
# commenting out for now until final shape is worked out
"""
@dataclass
class NVDInfo:

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

    cve_id: str
    description: str
    nvd: NVDInfo
"""

# probably discarding this later - changing to pydantic model_validator
"""
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
"""
