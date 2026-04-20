import click
import re
from .api import fetch_nvd_cve_data, fetch_ubusecapi_cve_data
from .models import NVDInfo
from .ui import display_cve_summary


CVE_REGEX = re.compile(
    r"\bCVE-(1999|2\d{3})-(0\d{2}[1-9]|[1-9]\d{3,})\b", re.IGNORECASE
)


def validate_cve(ctx, param, value):
    if not CVE_REGEX.match(value):
        raise click.BadParameter(
            f"{value} is not a valid CVE ID format (e.g., CVE-2021-4104)"
        )
    return value.upper()


@click.group()
@click.version_option()
def main():
    """cvesee: A tool for gathering and parsing CVE data"""
    pass


@main.command()
@click.option(
    "--source",
    "-s",
    type=click.Choice(["NVD", "GHSA", "UCT", "USAPI"], case_sensitive=False),
    default="NVD",
    help="""
        The CVE data source to query.
        Currently supported: NVD (Nist National Vulnerability Database), USAPI (Ubuntu Security API).
        Planned: GHSA (GitHub Security Advisories) and UCT (Ubuntu CVE Tracker)
    """,
)
@click.argument("cve_id", callback=validate_cve)
def info(source, cve_id):
    """Fetch and display details for a specific CVE ID"""
    wait_message = f"Status: Getting information about {cve_id} from {source}"
    source_fail_message = (
        f"Error: raw data from {source} not found - please try again later"
    )
    source_success_message = f"Status: Successfully retrieved data from {source}\n"
    parse_fail_message = f"\nError: Failed to parse data for {cve_id}:"

    match source:
        case "NVD":
            click.echo(wait_message)
            raw_nvd_data = fetch_nvd_cve_data(cve_id)
            if not raw_nvd_data:
                # something failed silently in the api call
                click.echo(source_fail_message)
                return

            try:
                click.echo(source_success_message)
                parsed_nvd_data = NVDInfo(**raw_nvd_data)
                display_cve_summary(parsed_nvd_data, source)
            except Exception as e:
                click.echo(parse_fail_message)
                click.echo(e)
        case "USAPI":
            click.echo(wait_message)
            raw_ubusec_data = fetch_ubusecapi_cve_data(cve_id)
            if not raw_ubusec_data:
                click.echo(source_fail_message)
                return

            # TODO: bookmark April 20, 2026
            try:
                pass
            except:
                pass
        case _:
            click.echo(
                f"Feature: supporting CVE info from {source} still in-progress - please try another source"
            )
            return


if __name__ == "__main__":
    main()
