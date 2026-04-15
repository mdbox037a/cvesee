import click
from rich import box
from rich.console import Console
from rich.table import Table
import re
from .api import fetch_nvd_cve_data
from .models import NVDInfo


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
    help="""
        The CVE data source to query.
        Currently supported: NVD (Nist National Vulnerability Database).
        Planned: GHSA (GitHub Security Advisories) and UCT (Ubuntu CVE Tracker)
    """,
)
@click.argument("cve_id", callback=validate_cve)
def info(source, cve_id):
    """Fetch and display details for a specific CVE ID"""
    if source == "NVD":
        click.echo(f"Status: Getting information about {cve_id} from {source}")
        raw_nvd_data = fetch_nvd_cve_data(cve_id)
        if not raw_nvd_data:
            # something failed silently in the api call
            click.echo(
                "Error: raw data from the NVD not found - please try again later"
            )
            return

        try:
            click.echo("Status: Successfully retrieved data from NVD\n")
            parsed_nvd_data = NVDInfo(**raw_nvd_data)
            # just splat flattened data to user, since no better parsing written yet
            # click.echo(f"\nStatus: Printing selected NVD data for {cve_id}:\n-----")
            # rich output setup and print
            console = Console()
            table = Table(
                title=f"{parsed_nvd_data.cve_id} | {source} Source Summary",
                title_justify="left",
                box=box.ASCII2,
                show_header=False,
                # width=80,
            )
            table.add_column(justify="right", no_wrap=True)
            table.add_column(justify="left")
            for element, value in parsed_nvd_data.model_dump().items():
                table.add_row(element.replace("_", " ").title(), str(value))
            # TODO: figure out how to print HttpUrls as strings
            # TODO: color output for severities?

            console.print(table)

        except Exception as e:
            click.echo(f"\nError: Failed to parse data for {cve_id}")
            click.echo(f"Error details: {e}")

    else:
        click.echo(
            f"Feature: supporting CVE info from {source} still in-progress - please try another source"
        )
        return


if __name__ == "__main__":
    main()
