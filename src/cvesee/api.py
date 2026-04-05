import requests
from cvesee import __version__


def fetch_nvd_cve_data(cve_id: str) -> dict | None:
    """get CVE data from NVD API and return JSON as dictionary"""

    nvd_api_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    params = {"cveId": cve_id}
    headers = {
        "user-agent": f"cvesee/{__version__} (https://github.com/mdbox037a/cvesee)"
    }

    try:
        r = requests.get(nvd_api_url, params=params, headers=headers, timeout=10)
        r.raise_for_status()
        return r.json()
    except requests.RequestException as e:
        print(f"Error requesting info for {cve_id}: {e}")
        return None
    except requests.Timeout:
        print("Request to NVD API timed out; please try again later")
        return None
