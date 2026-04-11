import click
import re
import inspect
from cvesee.api import fetch_nvd_cve_data


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
    type=click.Choice(["NVD", "GHSA", "UCT"], case_sensitive=False),
    default="NVD",
    help=inspect.cleandoc("""
        The CVE data source to query.
        
        Currently supported:
        - NVD (Nist National Vulnerability Database)

        Planned:
        - GHSA (GitHub Security Advisories)
        - UCT (Ubuntu CVE Tracker)
    """),
)
@click.argument("cve_id", callback=validate_cve)
def info(source, cve_id):
    """Fetch and display details for a specific CVE ID"""
    if source == "NVD":
        click.echo(f"### Getting information about {cve_id} from {source} ###")
        nvd_data = fetch_nvd_cve_data(cve_id)
        # just splat to screen for now, since we do not have any parsing written yet
        print(nvd_data)
    else:
        click.echo(f"{source} still in-progress - please try another source")
        return


if __name__ == "__main__":
    main()
