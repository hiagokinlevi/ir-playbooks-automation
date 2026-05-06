import json
import os
from pathlib import Path

import click


@click.group()
def cli():
    """IR Playbooks Automation CLI."""


def _markdown_to_basic_html(md_text: str) -> str:
    lines = md_text.splitlines()
    html_lines = []
    in_list = False

    for raw in lines:
        line = raw.rstrip()
        stripped = line.strip()

        if not stripped:
            if in_list:
                html_lines.append("</ul>")
                in_list = False
            continue

        if stripped.startswith("### "):
            if in_list:
                html_lines.append("</ul>")
                in_list = False
            html_lines.append(f"<h3>{stripped[4:]}</h3>")
        elif stripped.startswith("## "):
            if in_list:
                html_lines.append("</ul>")
                in_list = False
            html_lines.append(f"<h2>{stripped[3:]}</h2>")
        elif stripped.startswith("# "):
            if in_list:
                html_lines.append("</ul>")
                in_list = False
            html_lines.append(f"<h1>{stripped[2:]}</h1>")
        elif stripped.startswith("- ") or stripped.startswith("* "):
            if not in_list:
                html_lines.append("<ul>")
                in_list = True
            html_lines.append(f"<li>{stripped[2:]}</li>")
        else:
            if in_list:
                html_lines.append("</ul>")
                in_list = False
            html_lines.append(f"<p>{stripped}</p>")

    if in_list:
        html_lines.append("</ul>")

    return "\n".join(html_lines)


def _default_timeline_path() -> Path:
    return Path("templates/timelines/incident-timeline.md")


def _build_report_html(payload: dict, timeline_html: str | None = None) -> str:
    title = payload.get("title") or payload.get("incident_id") or "Incident Report"
    body = [
        "<!doctype html>",
        "<html>",
        "<head>",
        "  <meta charset='utf-8'>",
        f"  <title>{title}</title>",
        "  <style>body{font-family:Arial,sans-serif;max-width:900px;margin:2rem auto;line-height:1.5;} h1,h2,h3{margin-top:1.2rem;} pre{background:#f6f8fa;padding:1rem;overflow:auto;} section{margin-bottom:2rem;}</style>",
        "</head>",
        "<body>",
        f"<h1>{title}</h1>",
        "<section>",
        "<h2>Incident Data</h2>",
        f"<pre>{json.dumps(payload, indent=2)}</pre>",
        "</section>",
    ]

    if timeline_html:
        body.extend([
            "<section>",
            "<h2>Incident Timeline</h2>",
            timeline_html,
            "</section>",
        ])

    body.extend(["</body>", "</html>"])
    return "\n".join(body)


@cli.command("report-html")
@click.option("--input", "input_file", required=True, type=click.Path(exists=True, dir_okay=False, path_type=Path), help="Input incident JSON file")
@click.option("--output", "output_file", required=True, type=click.Path(dir_okay=False, path_type=Path), help="Output HTML file")
@click.option(
    "--include-timeline",
    "timeline_path",
    required=False,
    flag_value="__DEFAULT__",
    default=None,
    help="Embed timeline markdown/template section. Optionally pass a path.",
)
@click.option(
    "--timeline-file",
    "timeline_file",
    required=False,
    type=click.Path(exists=False, dir_okay=False, path_type=Path),
    help="Explicit timeline markdown/template file to embed (used with or without --include-timeline).",
)
def report_html(input_file: Path, output_file: Path, timeline_path: str | None, timeline_file: Path | None):
    """Generate an HTML incident report from JSON input."""
    with input_file.open("r", encoding="utf-8") as f:
        payload = json.load(f)

    include_timeline = timeline_path is not None or timeline_file is not None
    timeline_html = None

    if include_timeline:
        candidate = timeline_file
        if candidate is None:
            if timeline_path and timeline_path != "__DEFAULT__":
                candidate = Path(timeline_path)
            else:
                default_candidate = _default_timeline_path()
                candidate = default_candidate if default_candidate.exists() else None

        if candidate is None or not candidate.exists():
            click.echo("[warn] timeline file not found; continuing without timeline section", err=True)
        else:
            timeline_md = candidate.read_text(encoding="utf-8")
            timeline_html = _markdown_to_basic_html(timeline_md)

    html = _build_report_html(payload, timeline_html=timeline_html)
    output_file.parent.mkdir(parents=True, exist_ok=True)
    output_file.write_text(html, encoding="utf-8")
    click.echo(f"HTML report written: {output_file}")


if __name__ == "__main__":
    cli()
