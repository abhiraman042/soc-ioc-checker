
import getpass
import ipaddress
import os
import re
import time

import requests
from openpyxl import Workbook
from openpyxl.styles import Font, PatternFill, Alignment
from openpyxl.utils import get_column_letter
from openpyxl.formatting.rule import CellIsRule

API_URL = "https://www.virustotal.com/api/v3"
API_KEY = os.getenv("VIRUSTOTAL_API_KEY")

if not API_KEY:
    API_KEY = getpass.getpass("Enter your VirusTotal API key: ")

if not API_KEY.strip():
    raise SystemExit("No API key provided.")

HEADERS = {"x-apikey": API_KEY.strip()}


def identify_ioc(value):
    """Identify an IP address, file hash, or domain."""
    try:
        ipaddress.ip_address(value)
        return "ip_addresses"
    except ValueError:
        pass

    if re.fullmatch(
        r"[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64}",
        value
    ):
        return "files"

    if "." in value and " " not in value and "/" not in value:
        return "domains"

    return None


def check_ioc(value):
    """Check an IOC and determine its verdict."""
    ioc_type = identify_ioc(value)

    if not ioc_type:
        return [value, "Invalid or unsupported", "", "", "", "Unknown"]

    url = f"{API_URL}/{ioc_type}/{value}"

    try:
        response = requests.get(
            url, headers=HEADERS, timeout=20
        )

        if response.status_code == 404:
            return [value, "Not found", "", "", "", "Unknown"]

        response.raise_for_status()

        data = response.json()["data"]["attributes"]
        stats = data.get("last_analysis_stats")

        if not isinstance(stats, dict):
            return [value, "No analysis data", "", "", "", "Unknown"]

        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        harmless = stats.get("harmless", 0)

        if malicious > 0:
            verdict = "Malicious"
        elif suspicious > 0:
            verdict = "Suspicious"
        else:
            verdict = "Clean"

        return [
            value,
            "Lookup successful",
            malicious,
            suspicious,
            harmless,
            verdict
        ]

    except requests.HTTPError as error:
        if error.response is not None:
            code = error.response.status_code

            if code == 429:
                status = "Rate limited"
            else:
                status = f"HTTP error: {code}"
        else:
            status = "HTTP error"

        return [value, status, "", "", "", "Unknown"]

    except (requests.RequestException, ValueError, KeyError, TypeError):
        return [
            value, "Request or response error", "", "", "", "Unknown"
        ]



def save_excel(results):
    """Create an Excel report with a SOC dashboard and IOC details."""
    from openpyxl import Workbook
    from openpyxl.styles import Font, PatternFill, Alignment
    from openpyxl.utils import get_column_letter
    from openpyxl.chart import PieChart, Reference
    from openpyxl.formatting.rule import CellIsRule

    workbook = Workbook()

    # Dashboard sheet
    dashboard = workbook.active
    dashboard.title = "SOC Dashboard"

    dashboard["A1"] = "IOC CHECKER - SOC DASHBOARD"
    dashboard["A1"].font = Font(size=16, bold=True, color="FFFFFF")
    dashboard["A1"].fill = PatternFill(
        "solid", fgColor="1F4E78"
    )
    dashboard.merge_cells("A1:B1")

    dashboard["A3"] = "Metric"
    dashboard["B3"] = "Count"

    headers = ["Metric", "Count"]
    for cell in dashboard[3]:
        cell.font = Font(bold=True, color="FFFFFF")
        cell.fill = PatternFill("solid", fgColor="4472C4")

    total = len(results)
    malicious = sum(r[5] == "Malicious" for r in results)
    suspicious = sum(r[5] == "Suspicious" for r in results)
    clean = sum(r[5] == "Clean" for r in results)
    unknown = sum(r[5] == "Unknown" for r in results)

    metrics = [
        ("Total IOCs", total),
        ("Malicious", malicious),
        ("Suspicious", suspicious),
        ("Clean", clean),
        ("Unknown / Errors", unknown),
    ]

    for metric in metrics:
        dashboard.append(metric)

    dashboard.column_dimensions["A"].width = 25
    dashboard.column_dimensions["B"].width = 15

    # Pie chart for verdict distribution
    chart = PieChart()
    chart.title = "IOC Verdict Distribution"
    chart.style = 10
    chart.height = 8
    chart.width = 13

    chart_data = Reference(
        dashboard, min_col=2, min_row=4, max_row=8
    )
    chart_labels = Reference(
        dashboard, min_col=1, min_row=4, max_row=8
    )
    chart.add_data(chart_data, titles_from_data=False)
    chart.set_categories(chart_labels)
    dashboard.add_chart(chart, "D3")

    # IOC results sheet
    sheet = workbook.create_sheet("IOC Results")

    columns = [
        "Indicator", "Status", "Malicious",
        "Suspicious", "Harmless", "Verdict"
    ]
    sheet.append(columns)

    for result in results:
        sheet.append(result)

    for cell in sheet[1]:
        cell.font = Font(bold=True, color="FFFFFF")
        cell.fill = PatternFill("solid", fgColor="1F4E78")
        cell.alignment = Alignment(horizontal="center")

    widths = [28, 28, 14, 14, 14, 16]
    for index, width in enumerate(widths, start=1):
        sheet.column_dimensions[
            get_column_letter(index)
        ].width = width

    sheet.freeze_panes = "A2"
    sheet.auto_filter.ref = sheet.dimensions

    # Highlight verdicts
    verdict_range = f"F2:F{sheet.max_row}"

    verdict_styles = [
        ("Malicious", "FFC7CE", "9C0006"),
        ("Suspicious", "FFEB9C", "9C6500"),
        ("Clean", "C6EFCE", "006100"),
    ]

    for verdict, fill_color, font_color in verdict_styles:
        sheet.conditional_formatting.add(
            verdict_range,
            CellIsRule(
                operator="equal",
                formula=[f'"{verdict}"'],
                fill=PatternFill("solid", fgColor=fill_color),
                font=Font(color=font_color, bold=True),
            ),
        )

    workbook.save("results.xlsx")


def main():
    with open("iocs.txt", encoding="utf-8") as file:
        indicators = [
            line.strip()
            for line in file
            if line.strip() and not line.strip().startswith("#")
        ]

    results = []

    for index, indicator in enumerate(indicators):
        print(f"Checking {indicator}...")
        result = check_ioc(indicator)
        results.append(result)
        print(result)

        # Respect the typical VirusTotal public API rate limit.
        if index < len(indicators) - 1:
            time.sleep(20)

    save_excel(results)

    print("\nFinished. Results saved to results.xlsx")


if __name__ == "__main__":
    main()
