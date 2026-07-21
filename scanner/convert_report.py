#!/usr/bin/env python3
"""Convert AI Guard Confluence wiki markup report to proper HTML with inline CSS."""

import re
import sys
from pathlib import Path

INPUT = Path("/tmp/ai-guard-report.html")
OUTPUT = Path("/tmp/ai-guard-report-final.html")

# ── Styles ──────────────────────────────────────────────────────────────────

PAGE_CSS = (
    "font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;"
    "max-width: 1100px; margin: 0 auto; padding: 24px; color: #1a1a1a;"
    "line-height: 1.5; font-size: 14px;"
)
H1_CSS = "font-size: 26px; border-bottom: 2px solid #333; padding-bottom: 8px; margin-top: 32px;"
H2_CSS = "font-size: 20px; margin-top: 32px; border-bottom: 1px solid #ccc; padding-bottom: 6px;"
H3_CSS = "font-size: 15px; margin-top: 20px; margin-bottom: 4px; color: #333;"
TABLE_CSS = (
    "border-collapse: collapse; width: 100%; margin: 12px 0; font-size: 13px;"
)
TH_CSS = (
    "background: #f0f0f0; border: 1px solid #ccc; padding: 8px 10px;"
    "text-align: left; font-weight: 600;"
)
TD_CSS = "border: 1px solid #ddd; padding: 6px 10px;"
CODE_CSS = (
    "background: #f5f5f5; padding: 1px 5px; border-radius: 3px;"
    "font-family: 'SF Mono', Consolas, monospace; font-size: 12px;"
)
ITALIC_CSS = "color: #666; font-size: 13px;"

PANEL_COLOURS = {
    "red": {"border": "#d32f2f", "bg": "#fff5f5"},
    "#ff8b00": {"border": "#ff8b00", "bg": "#fff8f0"},
    "default": {"border": "#5b86e5", "bg": "#f5f8ff"},
}

RISK_BADGE = {
    "red": '<span style="font-size:14px;">&#x1F534;</span> <span style="color:#d32f2f;font-weight:700;">HIGH</span>',
    "#ff8b00": '<span style="font-size:14px;">&#x1F7E0;</span> <span style="color:#e68a00;font-weight:700;">MEDIUM</span>',
    "green": '<span style="font-size:14px;">&#x1F7E2;</span> <span style="color:#2e7d32;font-weight:700;">LOW</span>',
}

# ── Domain wrapping ─────────────────────────────────────────────────────────

DOMAIN_RE = re.compile(
    r"(?<![</\"=\w])"  # not inside a tag/attr
    r"([a-zA-Z0-9](?:[a-zA-Z0-9\-]*[a-zA-Z0-9])?"
    r"(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9\-]*[a-zA-Z0-9])?)*"
    r"\.(?:com|ai|net|org|io|co|co\.uk))"
    r"(?![/\w])"
)


def wrap_domains(text: str) -> str:
    """Wrap bare domain names in <code> tags so Confluence/email clients don't auto-link."""
    return DOMAIN_RE.sub(rf'<code style="{CODE_CSS}">\1</code>', text)


# ── Inline markup ───────────────────────────────────────────────────────────


def convert_inline(text: str) -> str:
    # {color:X}TEXT{color} -> risk badge or coloured span
    def _colour_sub(m):
        colour = m.group(1)
        body = m.group(2).strip()
        if body in ("HIGH", "MEDIUM", "LOW") and colour in RISK_BADGE:
            return RISK_BADGE[colour]
        if body == "OK" and colour == "green":
            return '<span style="color:#2e7d32;font-weight:600;">OK</span>'
        # Coloured inline text (e.g. tool names in panels)
        return f'<span style="color:{colour};font-weight:600;">{body}</span>'

    text = re.sub(r"\{color(?::([^}]*))?\}(.*?)\{color\}", _colour_sub, text)
    # {color:red}(!) -> warning icon
    text = text.replace("(!)", "&#9888;&#65039;")
    # *bold*
    text = re.sub(r"(?<!\w)\*([^*]+)\*(?!\w)", r"<strong>\1</strong>", text)
    # _italic_
    text = re.sub(r"(?<!\w)_([^_]+)_(?!\w)", rf'<em style="{ITALIC_CSS}">\1</em>', text)
    return text


# ── Block-level parsing ────────────────────────────────────────────────────


def parse(markup: str) -> str:
    lines = markup.splitlines()
    html_parts: list[str] = []
    i = 0
    in_list = False

    while i < len(lines):
        line = lines[i].rstrip()

        # Empty line
        if not line:
            if in_list:
                html_parts.append("</ul>")
                in_list = False
            i += 1
            continue

        # Panel end (must check before panel start since {panel} matches both)
        if line.strip() == "{panel}":
            if in_list:
                html_parts.append("</ul>")
                in_list = False
            html_parts.append("</div>")
            i += 1
            continue

        # Panel start
        panel_m = re.match(
            r"\{panel:([^}]+)\}", line
        )
        if panel_m:
            attrs = panel_m.group(1)
            title_m = re.search(r"title=([^|}]+)", attrs)
            border_m = re.search(r"borderColor=([^|}]+)", attrs)
            title = title_m.group(1) if title_m else ""
            colour_key = border_m.group(1) if border_m else "default"
            colours = PANEL_COLOURS.get(colour_key, PANEL_COLOURS["default"])
            html_parts.append(
                f'<div style="border-left:4px solid {colours["border"]};'
                f'background:{colours["bg"]};padding:14px 18px;margin:16px 0;'
                f'border-radius:4px;">'
            )
            if title:
                html_parts.append(
                    f'<div style="font-weight:700;font-size:15px;margin-bottom:8px;">{title}</div>'
                )
            i += 1
            continue

        # Headings
        h_m = re.match(r"^h([1-6])\.\s+(.*)", line)
        if h_m:
            if in_list:
                html_parts.append("</ul>")
                in_list = False
            level = h_m.group(1)
            text = convert_inline(h_m.group(2))
            text = wrap_domains(text)
            css = {1: H1_CSS, 2: H2_CSS, 3: H3_CSS}.get(int(level), "")
            style = f' style="{css}"' if css else ""
            html_parts.append(f"<h{level}{style}>{text}</h{level}>")
            i += 1
            continue

        # Table rows
        if line.startswith("||") or line.startswith("|"):
            if in_list:
                html_parts.append("</ul>")
                in_list = False
            is_header = line.startswith("||")
            sep = "||" if is_header else "|"
            # Split cells – strip leading/trailing separators
            raw = line.strip(sep).split(sep)
            cells = [c.strip() for c in raw]

            # Open table if previous part isn't a table
            if not html_parts or "</tr>" not in html_parts[-1]:
                html_parts.append(f'<table style="{TABLE_CSS}">')

            tag = "th" if is_header else "td"
            cell_css = TH_CSS if is_header else TD_CSS
            row = "<tr>" + "".join(
                f'<{tag} style="{cell_css}">{wrap_domains(convert_inline(c))}</{tag}>'
                for c in cells
            ) + "</tr>"
            html_parts.append(row)
            i += 1

            # If next line is NOT a table row, close the table
            next_line = lines[i].rstrip() if i < len(lines) else ""
            if not next_line.startswith("|"):
                html_parts.append("</table>")
            continue

        # Bullet list items
        if line.startswith("* "):
            if not in_list:
                html_parts.append('<ul style="margin:4px 0 4px 18px;padding:0;">')
                in_list = True
            content = convert_inline(line[2:])
            content = wrap_domains(content)
            html_parts.append(f'<li style="margin:3px 0;">{content}</li>')
            i += 1
            continue

        # Fallback: paragraph
        if in_list:
            html_parts.append("</ul>")
            in_list = False
        text = convert_inline(line)
        text = wrap_domains(text)
        html_parts.append(f"<p>{text}</p>")
        i += 1

    if in_list:
        html_parts.append("</ul>")

    return "\n".join(html_parts)


# ── Main ────────────────────────────────────────────────────────────────────


def main():
    src = sys.argv[1] if len(sys.argv) > 1 else str(INPUT)
    dst = sys.argv[2] if len(sys.argv) > 2 else str(OUTPUT)

    markup = Path(src).read_text(encoding="utf-8")
    body = parse(markup)

    html = f"""<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8"><title>AI Guard — Shadow AI Discovery Report</title></head>
<body style="{PAGE_CSS}">
{body}
</body>
</html>"""

    Path(dst).write_text(html, encoding="utf-8")
    print(f"Wrote {dst}  ({len(html):,} bytes)")


if __name__ == "__main__":
    main()
