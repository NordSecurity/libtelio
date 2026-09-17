"""Render the changelog markdown into a static HTML page for GitHub Pages.

Converts `changelog.md` (the format produced by `generate_changelog.py`) into an
HTML page that reuses the same styling assets as the rustdoc pages.

Usage:
    python3 ci/render_changelog.py \
        --in changelog.md \
        --out target/doc/changelog/index.html \
        --docs-index target/doc/index.html

The `markdown` package is required (install with `pip install markdown`).
"""

import argparse
import os
import re

import markdown

# Path back to the rustdoc index, relative to the changelog page
DOCS_HOME_HREF = "../index.html"

TITLE = "libtelio changelog"

# Placeholder series header for versions without a series name (e.g. "### ****").
# It carries no information so it is dropped.
EMPTY_SERIES_RE = re.compile(r"^###\s+\*+\s*$", re.MULTILINE)

# Link to the changelog injected into the rustdoc docs index page (see --docs-index).
DOCS_INDEX_LINK = (
    '<p style="margin:1rem 0;font-family:sans-serif"><a href="changelog/" '
    'style="font-size:1.15rem;font-weight:600;text-decoration:underline">'
    "View the changelog &rarr;</a></p>"
)
MAIN_CONTENT_RE = re.compile(r'(<section id="main-content"[^>]*>)')
BODY_RE = re.compile(r"(<body[^>]*>)")

PAGE_TEMPLATE = """\
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{title}</title>
{header}
<style>
  body {{ margin: 0; background: #fff; color: #1a1a1a;
         font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; }}
  .changelog {{ max-width: 900px; margin: 0 auto; padding: 2rem 1.5rem 4rem; }}
  .changelog nav {{ margin-bottom: 2rem; font-size: .9rem; }}
  .changelog h1 {{ font-size: 2rem; margin: 0 0 1.5rem; }}
  /* Version headers and their series-name subheaders (both rendered as <h3>). */
  .changelog h3 {{ font-size: 1.35rem; margin: 2rem 0 .25rem; }}
  .changelog h3 + h3 {{ font-size: 1rem; font-weight: 400; color: #666;
                        margin: 0 0 .5rem; }}
  .changelog hr {{ border: 0; border-top: 1px solid #e2e2e2; margin: .5rem 0 1rem; }}
  .changelog ul {{ line-height: 1.55; }}
  .changelog code {{ background: #f4f4f4; padding: .1em .35em; border-radius: 4px;
                     font-size: .9em; }}
  @media (prefers-color-scheme: dark) {{
    body {{ background: #0f1419; color: #e6e6e6; }}
    .changelog h3 + h3 {{ color: #9aa4ae; }}
    .changelog hr {{ border-top-color: #2a2f36; }}
    .changelog code {{ background: #1c232b; }}
    a {{ color: #6cb6ff; }}
  }}
</style>
</head>
<body>
<main class="changelog">
<nav><a href="{docs_home}">&larr; Back to docs</a></nav>
<h1>{title}</h1>
{body}
</main>
{footer}
</body>
</html>
"""


def read_optional(path):
    if path and os.path.isfile(path):
        with open(path, "r", encoding="utf-8") as f:
            return f.read()
    return ""


def render(md_text: str, header: str, footer: str) -> str:
    md_text = EMPTY_SERIES_RE.sub("", md_text)
    body_html = markdown.markdown(md_text, extensions=["extra", "sane_lists"])
    return PAGE_TEMPLATE.format(
        title=TITLE,
        header=header,
        footer=footer,
        body=body_html,
        docs_home=DOCS_HOME_HREF,
    )


def inject_docs_link(index_path: str) -> None:
    """Insert a link to the changelog into the rustdoc index page, in place."""
    with open(index_path, "r", encoding="utf-8") as f:
        html = f.read()
    html, n = MAIN_CONTENT_RE.subn(r"\1" + DOCS_INDEX_LINK, html, count=1)
    if n == 0:
        html, n = BODY_RE.subn(r"\1" + DOCS_INDEX_LINK, html, count=1)
    if n == 0:
        raise SystemExit(f"No changelog-link injection point found in {index_path}")
    with open(index_path, "w", encoding="utf-8") as f:
        f.write(html)
    print(f"Linked changelog from {index_path}")


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--in", dest="in_file", default="changelog.md")
    ap.add_argument("--out", dest="out_file", default="target/doc/changelog/index.html")
    ap.add_argument(
        "--header",
        default="rustdoc/header.html",
        help="HTML injected into <head> (shared rustdoc styling assets).",
    )
    ap.add_argument(
        "--footer",
        default="rustdoc/footer.html",
        help="HTML injected at end of <body> (shared rustdoc scripts).",
    )
    ap.add_argument(
        "--docs-index",
        help="If set, inject a link to the changelog into this rustdoc index.html.",
    )
    args = ap.parse_args()

    with open(args.in_file, "r", encoding="utf-8") as f:
        md_text = f.read()

    html = render(
        md_text,
        read_optional(args.header),
        read_optional(args.footer),
    )

    os.makedirs(os.path.dirname(os.path.abspath(args.out_file)), exist_ok=True)
    with open(args.out_file, "w", encoding="utf-8") as f:
        f.write(html)
    print(f"Wrote {args.out_file}")

    if args.docs_index:
        inject_docs_link(args.docs_index)


if __name__ == "__main__":
    main()
