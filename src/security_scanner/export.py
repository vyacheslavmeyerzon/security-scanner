"""
Export functionality for security scanner reports.
"""

import csv
import html
import json
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional


class ReportGenerator:
    """Generate reports in various formats."""

    def __init__(
        self,
        findings: List[Dict[str, Any]],
        scan_stats: Optional[Dict[str, Any]] = None,
    ):
        """
        Initialize report generator.

        Args:
            findings: List of security findings
            scan_stats: Optional scanning statistics
        """
        self.findings = findings
        self.scan_stats = scan_stats or {}
        self.timestamp = datetime.now()

    def generate_statistics(self) -> Dict[str, Any]:
        """Generate statistics from findings."""
        stats = {
            "total_findings": len(self.findings),
            "by_severity": Counter(f["severity"] for f in self.findings),
            "by_type": Counter(f["type"] for f in self.findings),
            "by_file": defaultdict(list),
            "most_common_types": [],
            "files_with_most_findings": [],
            "scan_timestamp": self.timestamp.isoformat(),
        }

        # Group findings by file
        for finding in self.findings:
            stats["by_file"][finding["file"]].append(finding)

        # Calculate most common secret types
        stats["most_common_types"] = [
            {"type": type_name, "count": count}
            for type_name, count in stats["by_type"].most_common(10)
        ]

        # Calculate files with most findings
        file_counts = [
            (file, len(findings)) for file, findings in stats["by_file"].items()
        ]
        file_counts.sort(key=lambda x: x[1], reverse=True)
        stats["files_with_most_findings"] = [
            {"file": file, "count": count} for file, count in file_counts[:10]
        ]

        # Add scan statistics if available
        stats.update(self.scan_stats)

        return stats

    def export_to_csv(self, output_path: Path) -> None:
        """
        Export findings to CSV format.

        Args:
            output_path: Path to save CSV file
        """
        fieldnames = [
            "severity",
            "type",
            "file",
            "line",
            "column",
            "secret",
            "description",
            "commit",
        ]

        with open(output_path, "w", newline="", encoding="utf-8") as csvfile:
            writer = csv.DictWriter(
                csvfile, fieldnames=fieldnames, extrasaction="ignore"
            )
            writer.writeheader()

            for finding in self.findings:
                # Create a copy to avoid modifying original
                row = finding.copy()
                # Truncate secret for security if it's long
                if "secret" in row and len(row["secret"]) > 50:
                    row["secret"] = row["secret"][:20] + "..." + row["secret"][-20:]
                writer.writerow(row)

    def export_to_html(self, output_path: Path) -> None:
        """
        Export findings to HTML report.

        Args:
            output_path: Path to save HTML file
        """
        stats = self.generate_statistics()
        html_content = self._generate_html_report(stats)
        output_path.write_text(html_content, encoding="utf-8")

    def _generate_html_report(self, stats: Dict[str, Any]) -> str:
        """Generate HTML report content."""
        # HTML template with embedded CSS and JavaScript
        html_template = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Scanner Report - {timestamp}</title>
    <style>
        :root {{
            --primary-color: #2563eb;
            --danger-color: #dc2626;
            --warning-color: #f59e0b;
            --info-color: #8b5cf6;
            --success-color: #10b981;
            --bg-color: #f9fafb;
            --text-color: #1f2937;
            --border-color: #e5e7eb;
        }}

        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}

        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;  # noqa: E501
            background-color: var(--bg-color);
            color: var(--text-color);
            line-height: 1.6;
            padding: 20px;
        }}

        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background-color: white;
            border-radius: 8px;
            box-shadow: 0 1px 3px rgba(0, 0, 0, 0.1);
            padding: 30px;
        }}

        h1, h2, h3 {{
            margin-bottom: 20px;
        }}

        h1 {{
            color: var(--primary-color);
            border-bottom: 2px solid var(--border-color);
            padding-bottom: 10px;
        }}

        .summary {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }}

        .stat-card {{
            background-color: var(--bg-color);
            padding: 20px;
            border-radius: 8px;
            text-align: center;
            border: 1px solid var(--border-color);
        }}

        .stat-card h3 {{
            font-size: 2em;
            margin-bottom: 5px;
        }}

        .severity-critical {{ color: var(--danger-color); }}
        .severity-high {{ color: var(--warning-color); }}
        .severity-medium {{ color: var(--info-color); }}
        .severity-low {{ color: var(--success-color); }}

        .findings-table {{
            width: 100%;
            border-collapse: collapse;
            margin-top: 20px;
        }}

        .findings-table th,
        .findings-table td {{
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid var(--border-color);
        }}

        .findings-table th {{
            background-color: var(--bg-color);
            font-weight: 600;
            position: sticky;
            top: 0;
            cursor: pointer;
        }}

        .findings-table th:hover {{
            background-color: #e5e7eb;
        }}

        .findings-table tr:hover {{
            background-color: #f9fafb;
        }}

        .severity-badge {{
            display: inline-block;
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 0.875em;
            font-weight: 500;
        }}

        .severity-badge.critical {{
            background-color: #fee2e2;
            color: var(--danger-color);
        }}

        .severity-badge.high {{
            background-color: #fef3c7;
            color: var(--warning-color);
        }}

        .severity-badge.medium {{
            background-color: #ede9fe;
            color: var(--info-color);
        }}

        .severity-badge.low {{
            background-color: #d1fae5;
            color: var(--success-color);
        }}

        .secret-preview {{
            font-family: monospace;
            font-size: 0.875em;
            background-color: #f3f4f6;
            padding: 2px 4px;
            border-radius: 2px;
        }}

        .filter-controls {{
            margin-bottom: 20px;
            display: flex;
            gap: 15px;
            flex-wrap: wrap;
        }}

        .filter-controls select,
        .filter-controls input {{
            padding: 8px 12px;
            border: 1px solid var(--border-color);
            border-radius: 4px;
            font-size: 0.875em;
        }}

        .chart-container {{
            margin: 30px 0;
            padding: 20px;
            background-color: var(--bg-color);
            border-radius: 8px;
        }}

        .chart-bar {{
            display: flex;
            align-items: center;
            margin-bottom: 10px;
        }}

        .chart-label {{
            width: 150px;
            font-size: 0.875em;
        }}

        .chart-value {{
            height: 25px;
            background-color: var(--primary-color);
            color: white;
            display: flex;
            align-items: center;
            padding: 0 10px;
            border-radius: 4px;
            font-size: 0.875em;
            font-weight: 500;
        }}

        .footer {{
            margin-top: 40px;
            padding-top: 20px;
            border-top: 1px solid var(--border-color);
            text-align: center;
            color: #6b7280;
            font-size: 0.875em;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>Security Scanner Report</h1>
        <p>Generated on {timestamp}</p>

        <div class="summary">
            <div class="stat-card">
                <h3>{total_findings}</h3>
                <p>Total Findings</p>
            </div>
            <div class="stat-card">
                <h3 class="severity-critical">{critical_count}</h3>
                <p>Critical</p>
            </div>
            <div class="stat-card">
                <h3 class="severity-high">{high_count}</h3>
                <p>High</p>
            </div>
            <div class="stat-card">
                <h3 class="severity-medium">{medium_count}</h3>
                <p>Medium</p>
            </div>
            <div class="stat-card">
                <h3 class="severity-low">{low_count}</h3>
                <p>Low</p>
            </div>
            <div class="stat-card">
                <h3>{scanned_files}</h3>
                <p>Files Scanned</p>
            </div>
        </div>

        <h2>Top Secret Types</h2>
        <div class="chart-container">
            {type_chart}
        </div>

        <h2>Files with Most Findings</h2>
        <div class="chart-container">
            {file_chart}
        </div>

        <h2>Detailed Findings</h2>
        <div class="filter-controls">
            <input type="text" id="searchInput" placeholder="Search findings..." onkeyup="filterTable()">  # noqa: E501
            <select id="severityFilter" onchange="filterTable()">
                <option value="">All Severities</option>
                <option value="CRITICAL">Critical</option>
                <option value="HIGH">High</option>
                <option value="MEDIUM">Medium</option>
                <option value="LOW">Low</option>
            </select>
            <select id="typeFilter" onchange="filterTable()">
                <option value="">All Types</option>
                {type_options}
            </select>
        </div>

        <table class="findings-table" id="findingsTable">
            <thead>
                <tr>
                    <th onclick="sortTable(0)">Severity ↕</th>
                    <th onclick="sortTable(1)">Type ↕</th>
                    <th onclick="sortTable(2)">File ↕</th>
                    <th onclick="sortTable(3)">Line ↕</th>
                    <th>Secret</th>
                    <th>Description</th>
                </tr>
            </thead>
            <tbody>
                {findings_rows}
            </tbody>
        </table>

        <div class="footer">
            <p>Generated by Git Security Scanner</p>
        </div>
    </div>

    <script>
        function filterTable() {{
            const input = document.getElementById('searchInput');
            const severityFilter = document.getElementById('severityFilter');
            const typeFilter = document.getElementById('typeFilter');
            const filter = input.value.toUpperCase();
            const table = document.getElementById('findingsTable');
            const tr = table.getElementsByTagName('tr');

            for (let i = 1; i < tr.length; i++) {{
                const td = tr[i].getElementsByTagName('td');
                let display = true;

                // Text search
                if (filter) {{
                    let textFound = false;
                    for (let j = 0; j < td.length; j++) {{
                        if (td[j] && td[j].textContent.toUpperCase().indexOf(filter) > -1) {{
                            textFound = true;
                            break;
                        }}
                    }}
                    display = display && textFound;
                }}

                // Severity filter
                if (severityFilter.value && td[0]) {{
                    display = display && td[0].textContent.trim() === severityFilter.value;
                }}

                // Type filter
                if (typeFilter.value && td[1]) {{
                    display = display && td[1].textContent.trim() === typeFilter.value;
                }}

                tr[i].style.display = display ? '' : 'none';
            }}
        }}

        function sortTable(n) {{
            const table = document.getElementById('findingsTable');
            let rows, switching, i, x, y, shouldSwitch, dir, switchcount = 0;
            switching = true;
            dir = 'asc';

            while (switching) {{
                switching = false;
                rows = table.rows;

                for (i = 1; i < (rows.length - 1); i++) {{
                    shouldSwitch = false;
                    x = rows[i].getElementsByTagName('TD')[n];
                    y = rows[i + 1].getElementsByTagName('TD')[n];

                    if (dir == 'asc') {{
                        if (x.innerHTML.toLowerCase() > y.innerHTML.toLowerCase()) {{
                            shouldSwitch = true;
                            break;
                        }}
                    }} else if (dir == 'desc') {{
                        if (x.innerHTML.toLowerCase() < y.innerHTML.toLowerCase()) {{
                            shouldSwitch = true;
                            break;
                        }}
                    }}
                }}

                if (shouldSwitch) {{
                    rows[i].parentNode.insertBefore(rows[i + 1], rows[i]);
                    switching = true;
                    switchcount++;
                }} else {{
                    if (switchcount == 0 && dir == 'asc') {{
                        dir = 'desc';
                        switching = true;
                    }}
                }}
            }}
        }}
    </script>
</body>
</html>"""

        # Generate type options for filter
        type_options = "\n".join(
            f'<option value="{html.escape(t["type"])}">{html.escape(t["type"])} ({t["count"]})</option>'  # noqa: E501
            for t in stats["most_common_types"]
        )

        # Generate type chart
        max_count = max((t["count"] for t in stats["most_common_types"]), default=1)
        type_chart = "\n".join(
            f"""<div class="chart-bar">
                <div class="chart-label">{html.escape(t["type"])}</div>
                <div class="chart-value" style="width: {t["count"] / max_count * 400}px;">  # noqa: E501
                    {t["count"]}
                </div>
            </div>"""
            for t in stats["most_common_types"][:10]
        )

        # Generate file chart
        max_file_count = max(
            (f["count"] for f in stats["files_with_most_findings"]), default=1
        )  # noqa: E501
        file_chart = "\n".join(
            f"""<div class="chart-bar">
                <div class="chart-label">{html.escape(f["file"][:30] + "..." if len(f["file"]) > 30 else f["file"])}</div>  # noqa: E501
                <div class="chart-value" style="width: {f["count"] / max_file_count * 400}px;">  # noqa: E501
                    {f["count"]}
                </div>
            </div>"""
            for f in stats["files_with_most_findings"][:10]
        )

        # Generate findings rows
        findings_rows = "\n".join(
            f"""<tr>
                <td><span class="severity-badge {finding['severity'].lower()}">{finding['severity']}</span></td>  # noqa: E501
                <td>{html.escape(finding['type'])}</td>
                <td>{html.escape(finding['file'])}</td>
                <td>{finding.get('line', 'N/A')}</td>
                <td><code class="secret-preview">{html.escape(finding.get('secret', 'N/A')[:50])}</code></td>
                <td>{html.escape(finding.get('description', ''))}</td>
            </tr>"""
            for finding in self.findings
        )

        # Fill in the template
        return html_template.format(
            timestamp=self.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
            total_findings=stats["total_findings"],
            critical_count=stats["by_severity"].get("CRITICAL", 0),
            high_count=stats["by_severity"].get("HIGH", 0),
            medium_count=stats["by_severity"].get("MEDIUM", 0),
            low_count=stats["by_severity"].get("LOW", 0),
            scanned_files=stats.get("scanned_files", "N/A"),
            type_options=type_options,
            type_chart=type_chart,
            file_chart=file_chart,
            findings_rows=findings_rows,
        )

    def export_to_json_with_stats(self, output_path: Path) -> None:
        """
        Export findings with statistics to JSON.

        Args:
            output_path: Path to save JSON file
        """
        stats = self.generate_statistics()
        data = {
            "metadata": {
                "timestamp": self.timestamp.isoformat(),
                "version": "1.0",
            },
            "statistics": stats,
            "findings": self.findings,
        }

        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, default=str)

    def export_to_markdown(self, output_path: Path) -> None:
        """
        Export findings to Markdown format.

        Args:
            output_path: Path to save Markdown file
        """
        stats = self.generate_statistics()

        md_content = f"""# Security Scanner Report

Generated on: {self.timestamp.strftime("%Y-%m-%d %H:%M:%S")}

## Summary

- **Total Findings**: {stats['total_findings']}
- **Critical**: {stats['by_severity'].get('CRITICAL', 0)}
- **High**: {stats['by_severity'].get('HIGH', 0)}
- **Medium**: {stats['by_severity'].get('MEDIUM', 0)}
- **Low**: {stats['by_severity'].get('LOW', 0)}
- **Files Scanned**: {stats.get('scanned_files', 'N/A')}

## Top Secret Types

| Type | Count |
|------|-------|
"""
        for t in stats["most_common_types"][:10]:
            md_content += f"| {t['type']} | {t['count']} |\n"

        md_content += (
            "\n## Files with Most Findings\n\n| File | Count |\n|------|-------|\n"
        )
        for f in stats["files_with_most_findings"][:10]:
            md_content += f"| {f['file']} | {f['count']} |\n"

        md_content += "\n## Detailed Findings\n\n"

        # Group findings by severity
        for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            severity_findings = [f for f in self.findings if f["severity"] == severity]
            if severity_findings:
                md_content += f"\n### {severity} Severity\n\n"
                for finding in severity_findings:
                    md_content += f"- **{finding['type']}** in `{finding['file']}:{finding.get('line', 'N/A')}`\n"  # noqa: E501
                    md_content += (
                        f"  - {finding.get('description', 'No description')}\n"
                    )
                    md_content += (
                        f"  - Secret: `{finding.get('secret', 'N/A')[:30]}...`\n\n"
                    )

        output_path.write_text(md_content, encoding="utf-8")
