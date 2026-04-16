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
    for element, info in parsed_cve_data.model_dump(mode="json").items():
        match info:
            case str():
                pretty_info = info
                if pretty_info in SEVERITY_COLORS:
                    pretty_info = SEVERITY_COLORS[pretty_info]
            case list():
                pretty_info = "\n".join(info) if info else "[dim]None[/dim]"
            case dict():
                package_lines = []
                for vendor, products in info.items():
                    product_str = ", ".join(products)
                    package_lines.append(f"[dim]{vendor}[/dim]: {product_str}")
                pretty_info = (
                    "\n".join(package_lines) if package_lines else "[dim]None[/dim]"
                )
            case None:
                pretty_info = f"[dim]{info}[/dim]"
            case _:
                pretty_info = str(info)
        table.add_row(element.replace("_", " ").title(), pretty_info)

    console.print(table)
