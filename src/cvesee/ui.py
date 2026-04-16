from rich.table import Table
from rich import box
from rich.console import Console


def display_cve_summary(parsed_cve_data: dict, source: str) -> None:
    """use rich to format parsed NVD CVE info and send to console"""
    console = Console()
    table = Table(
        title=f"{parsed_cve_data.cve_id} | {source} Source Summary",
        title_justify="left",
        box=box.ASCII2,
        show_header=False,
    )
    table.add_column(justify="right", no_wrap=True)
    table.add_column(justify="left")
    for element, value in parsed_cve_data.model_dump().items():
        table.add_row(element.replace("_", " ").title(), str(value))
    # TODO: figure out how to print HttpUrls as strings
    # TODO: color output for severities?

    console.print(table)
