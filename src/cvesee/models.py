from pydantic import BaseModel, model_validator, HttpUrl
from datetime import datetime
from typing import List, Optional
from .utils import parse_cpe
from collections import defaultdict


class NVDInfo(BaseModel):
    """pydantic model to parse selected NVD CVE API data"""

    cve_id: str
    packages: Optional[dict[str, list[str]]] = None
    reporting_cna: Optional[str] = None
    cna_score: Optional[float] = None
    cna_severity: Optional[str] = None
    nist_evaluated: Optional[bool] = False
    nist_score: Optional[float] = None
    nist_severity: Optional[str] = None
    description: str
    date_published: datetime
    date_last_modified: datetime
    date_accessed: datetime
    cve_tags: Optional[List[str]] = None
    vendor_advisories: Optional[List[HttpUrl]] = None
    patches: Optional[List[HttpUrl]] = None

    @model_validator(mode="before")
    @classmethod
    def flatten(cls, nvd_data: dict) -> dict:
        """
        ingest NVD API JSON output and return flattened data of interest for pydantic to
        use to populate NVDInfo class fields
        """

        # initialize dict to return to pydantic (only required keys or keys required
        # to avoid breaks in parsing logic below)
        flat_data = {
            "cve_id": "",
            "packages": {},
            "description": "",
            "date_published": "",
            "date_last_modified": "",
            "date_accessed": "",
            "vendor_advisories": [],
            "patches": [],
            "reporting_cna": None,
        }

        c_wrap = nvd_data.get("vulnerabilities", [{}])[0].get("cve", {})
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
                    if "nist" in item["source"] and not flat_data.get("nist_evaluated"):
                        flat_data["nist_evaluated"] = True
                        flat_data["nist_score"] = cvss_data.get("baseScore")
                        flat_data["nist_severity"] = cvss_data.get("baseSeverity")
                    elif (
                        not flat_data.get("reporting_cna")
                        and "nist" not in item["source"]
                    ):
                        # if we already have a reporting cna, skip
                        flat_data["reporting_cna"] = item["source"]
                        flat_data["cna_score"] = cvss_data.get("baseScore")
                        flat_data["cna_severity"] = cvss_data.get("baseSeverity")

                # once we've captured one set of CVSS data, break, since we
                # are moving in order from v4.0 -> 3.1 -> 3.0 -> 2
                if flat_data.get("nist_evaluated") and flat_data.get("reporting_cna"):
                    break

        # get english language cve description
        descriptions = c_wrap.get("descriptions", [])
        for desc in descriptions:
            if desc["lang"] == "en":
                flat_data["description"] = desc["value"]

                # once we've captured the english string, break
                break

        # get vendor and product from configurations madness
        conf_wrap = c_wrap.get("configurations", [])
        all_criteria = [
            match.get("criteria")
            for conf in conf_wrap
            for node in conf.get("nodes", [])
            for match in node.get("cpeMatch", [])
            if match.get("criteria")
        ]

        packages = defaultdict(set)
        for criteria in all_criteria:
            vendor, product = parse_cpe(criteria)
            packages[vendor].add(product)

        flat_data["packages"] = packages

        # get vendor advisories and references
        references = c_wrap.get("references", [])
        for ref in references:
            tags = ref.get("tags", [])
            if "Vendor Advisory" in tags:
                flat_data["vendor_advisories"].append(ref["url"])
            if "Patch" in tags:
                flat_data["patches"].append(ref["url"])

        # fill out the rest of the fields from the 'cve' wrapper
        flat_data["cve_id"] = c_wrap.get("id")
        flat_data["date_published"] = c_wrap.get("published")
        flat_data["date_last_modified"] = c_wrap.get("lastModified")
        flat_data["date_accessed"] = nvd_data["timestamp"]
        flat_data["cve_tags"] = c_wrap.get("cve_tags", [])

        return flat_data


class UbuSecAPIInfo(BaseModel):
    """pydantic model to hold parsed Ubuntu security API data"""

    cve_id: str
    packages: Optional[dict[str, list[str]]] = None
    nvd_score: Optional[float] = None
    nvd_severity: Optional[str] = None
    ubuntu_priority: Optional[str] = None
    description: str
    canonical_notes: Optional[str] = None
    date_published: datetime
    date_last_modified: datetime
    date_accessed: datetime
    notices: Optional[List[str]] = None
    updated_packages: Optional[List[str]] = None
