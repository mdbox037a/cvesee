import requests
from cvesee import __version__


headers = {"user-agent": f"cvesee/{__version__} (https://github.com/mdbox037a/cvesee)"}


def fetch_nvd_cve_data(cve_id: str) -> dict | None:
    """get CVE data from NVD API and return JSON as dictionary"""

    nvd_api_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    params = {"cveId": cve_id}

    try:
        nvd_data = requests.get(nvd_api_url, params=params, headers=headers, timeout=10)
        nvd_data.raise_for_status()
        return nvd_data.json()
    except requests.RequestException as e:
        print(f"Error requesting info for {cve_id}: {e}")
        return None
    except requests.Timeout:
        print("Request to NVD API timed out; please try again later")
        return None


def fetch_usapi_cve_data(cve_id: str) -> dict | None:
    """get CVE data from Ubuntu security API and return JSON as dictionary"""

    ubusec_api_url = f"https://ubuntu.com/security/cves/{cve_id}.json"

    try:
        ubusec_data = requests.get(ubusec_api_url, headers=headers, timeout=10)
        ubusec_data.raise_for_status()
        return ubusec_data.json()
    except requests.RequestException as e:
        print(f"Error requesting info for {cve_id}: {e}")
        return None
    except requests.Timeout:
        print("Request to Ubuntu security API timed out; please try again later")
        return None
