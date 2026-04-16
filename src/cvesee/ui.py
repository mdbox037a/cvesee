from rich.table import Table
from rich import box
from rich.console import Console


SEVERITY_COLORS = {
    "CRITICAL": "[dark_red]CRITICAL[/dark_red]",
    "HIGH": "[red]HIGH[/red]",
    "MEDIUM": "[magenta]MEDIUM[/magenta]",
    "LOW": "[blue]LOW[/blue]",
}


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
    for element, value in parsed_cve_data.model_dump(mode="json").items():
        match value:
            case list():
                pretty_value = "\n".join(value) if value else "[dim]None[/dim]"
            case None:
                pretty_value = f"[dim]{value}[/dim]"
            case _:
                pretty_value = str(value)
        if pretty_value in SEVERITY_COLORS:
            pretty_value = SEVERITY_COLORS[pretty_value]
        table.add_row(element.replace("_", " ").title(), pretty_value)

    console.print(table)
