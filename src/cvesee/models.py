from pydantic import BaseModel, Field, model_validator, HttpUrl
from dataclasses import dataclass
from datetime import datetime
from typing import List, Any, Optional


class NVDInfo(BaseModel):
    cve_id: str
    rcna_score: Optional[float] = None
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
        c_wrap = nvd_data.get("vulnerabilities", [{}]).get("cve", {})
        m_wrap = c_wrap.get("metrics", {})
        # set cvss version preference order
        versions = [
            "cvssMetricV40",
            "cvssMetricV31",
            "cvssMetricV30",
            "cvssMetricV2",
        ]

        # get deeply nested data from 'metrics' wrapper
        for m_ver in versions:
            if m_ver in m_wrap:
                for index, item in enumerate(m_wrap[m_ver]):
                    cvss_data = m_wrap[m_ver][index].get("cvssData", {})
                    if item["source"] == "nist@nist.gov":
                        nvd_data["nist_cna"] = True
                        nvd_data["nist_score"] = cvss_data.get("baseScore")
                        nvd_data["nist_severity"] = cvss_data.get("baseSeverity")
                    elif not nvd_data["reporting_cna"]:
                        # if we already have a reporting cna, skip
                        nvd_data["reporting_cna"] = item["source"]
                        nvd_data["rcna_score"] = cvss_data.get("baseScore")
                        nvd_data["cna_severity"] = cvss_data.get("baseSeverity")

                # once we've captured one set of CVSS data, break, since we
                # are moving in order from v4.0 -> 3.1 -> 3.0 -> 2
                break

        # get english language cve description
        descriptions = c_wrap.get("descriptions", [])
        for desc in descriptions:
            if desc["lang"] == "en":
                nvd_data["description"] = desc["value"]

                # once we've captured the english string, break
                break

        # get vendor advisories and references
        references = c_wrap.get("references", [])
        for ref in references:
            if "Vendor Advisory" in ref["tags"]:
                nvd_data["vendor_advisories"].append(ref["url"])
            if "Patch" in ref["tags"]:
                nvd_data["patches"].append(ref["url"])

        # fill out the rest of the fields from the 'cve' wrapper
        nvd_data["cve_id"] = c_wrap.get("id")
        nvd_data["date_published"] = c_wrap.get("published")
        nvd_data["date_last_modified"] = c_wrap.get("lastModified")
        nvd_data["date_accessed"] = nvd_data["timestamp"]
        nvd_data["cve_tags"] = c_wrap.get("cve_tags", [])
