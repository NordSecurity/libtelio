import os
import sys
import argparse
import re
from typing import Optional

from markdown_it import MarkdownIt
from packaging.version import Version, InvalidVersion


# Regexes for ticket number in filename
TICKET_NUMBER = r"^([a-zA-Z]{1,10})[\s_-]?(\d{1,6})"
# A version heading's text, e.g. "v8.0.0-rc2" or legacy "5.0.0" (the `v` is optional).
# Applied to a parsed `### ` heading's text to tell version headings from series names.
VERSION_HEADING = r"^v?\d\S*$"

# Python automatically translates the '\n' escape character for cross platform compatibility.
# Format use to print the version at the beginning of the new version entry in the changelog.
HEADER_FORMAT = "### {}\n### **{}**\n---\n"
# Format for actual every version entry, when ticket number found.
ENTRY_FORMAT_W_TICKET = "* {}: {}\n"
# Same as ^^^, but when ticket number not found
ENTRY_FORMAT_WO_TICKET = "* {}\n"
# Format use to print the ending of the new version entry in the changelog.
VERSION_ENDING = "\n<br>\n\n"

# A line at the top of the changelog file to indicate that it's auto-generated.
AUTO_GENERATION_NOTE_LINE = (
    "<!-- Note: this file is auto-generated. See CONTRIBUTING.md for details. -->\n\n"
)

TICKET_NUMBER_REGEX = re.compile(TICKET_NUMBER, re.I)
VERSION_HEADING_REGEX = re.compile(VERSION_HEADING)


def _match_ticket(input_str: str) -> Optional[str]:
    match = TICKET_NUMBER_REGEX.search(input_str)
    if match:
        letters = match.group(1).upper()  # e.g. 'llt' -> 'LLT'
        numbers = match.group(2)  # e.g. '1234'
        return f"{letters}-{numbers}"
    return None


def _sort_key(version: str) -> Version:
    """Parse a version string for sorting. Unparseable headers sort lowest."""
    try:
        return Version(version)
    except InvalidVersion:
        return Version("0")


def _line_start_offsets(text: str) -> list:
    """For each line, give the character position where it starts"""
    offsets = [0]
    for line in text.split("\n"):
        offsets.append(offsets[-1] + len(line) + 1)
    return offsets


def _version_headings(body: str) -> list:
    """Find every '### <version>' heading and return [(version, char_offset), ...]
    from top to bottom."""
    tokens = MarkdownIt().parse(body)
    offsets = _line_start_offsets(body)
    headings = []
    for i, token in enumerate(tokens):
        if token.type == "heading_open" and token.tag == "h3" and token.map:
            heading_text = tokens[i + 1].content.strip()
            if VERSION_HEADING_REGEX.match(heading_text):
                headings.append((heading_text, offsets[token.map[0]]))
    return headings


def insert_block_sorted(body: str, block: str, out_version: str) -> str:
    """Insert `block` into `body` (version blocks, newest-first) keeping semver order.
    If `out_version` already has a block, replace it, so re-runs don't duplicate it."""
    new_key = _sort_key(out_version)
    headings = _version_headings(body)
    # Block already exists: replace.
    for i, (version, offset) in enumerate(headings):
        if version == out_version:
            end = headings[i + 1][1] if i + 1 < len(headings) else len(body)
            return body[:offset] + block + body[end:]
    # Otherwise insert before the first older version.
    for version, offset in headings:
        if _sort_key(version) < new_key:
            return body[:offset] + block + body[offset:]
    # Empty changelog, or the new version is the oldest.
    return block if not body else body + block


def insert_block_into_file(out_file: str, block: str, out_version: str) -> None:
    """Insert `block` into the changelog file, keeping the auto-generation note.
    Shared by the CLI and ci/release.py."""
    with open(out_file, "r", encoding="utf-8") as f:
        content = f.read()
    body = (
        content[len(AUTO_GENERATION_NOTE_LINE) :]
        if content.startswith(AUTO_GENERATION_NOTE_LINE)
        else content
    )
    new_body = insert_block_sorted(body, block, out_version)
    with open(out_file, "w", encoding="utf-8") as f:
        f.write(AUTO_GENERATION_NOTE_LINE + new_body)


def gather_output(
    unreleased_dir: str, out_version: str, out_series_name: str, delete_files: bool
) -> Optional[str]:
    """Function that handles gathering all the changelog entries from the unreleased dir
    into a string. Returns None, if there are no entries.

    Args:
        unreleased_dir (str):   path into (and including) .unreleased directory where all the
                                files with the change descriptions are stored.
        out_version (str):      Version of the release that's being made.
        out_series_name (str):  Version series name (like android lollipop).
        delete_files (bool):    Remove each processed file from the unreleased dir.

    Returns:
        Optional[str]: The aggregated entries including the header and footer to
                       insert into the changelog file.
    """

    # Git drops empty dirs, so .unreleased may be gone after the last file is used.
    if not os.path.isdir(unreleased_dir):
        return None

    # The following bool is used to prevent unwanted behavior
    # when no version entries are present in the new version directory.
    at_least_one_entry_found = False

    output = HEADER_FORMAT.format(out_version, out_series_name)

    for changelog_entry_file in os.scandir(unreleased_dir):
        with open(changelog_entry_file, "r", encoding="utf-8") as changelog_entry_file:
            for line in changelog_entry_file.readlines():
                if not line.strip():
                    continue
                at_least_one_entry_found = True
                filename = os.path.basename(changelog_entry_file.name)
                entry_ticket_id = _match_ticket(filename)

                if entry_ticket_id is not None:
                    output += ENTRY_FORMAT_W_TICKET.format(
                        entry_ticket_id, line.strip()
                    )
                else:
                    output += ENTRY_FORMAT_WO_TICKET.format(line.strip())
        if delete_files:
            os.remove(changelog_entry_file.name)
    output += VERSION_ENDING

    return output if at_least_one_entry_found else None


def parse_args():
    """Function that handles parsing the cli args if this function is used as
    a standalone script."""

    parser = argparse.ArgumentParser(
        description="""\
        Changelog aggregator.

        Aggregates `changelog.md` file from all the files in .unreleased directory each containing
        a single change description in text format. Each of these files should be named after
        their corresponding ticket ID, so the file structure should be as follows:

        ├── .unreleased
        │   ├── ABC-0001
        │   ├── ABC-0002
        │   ├── ABC-0054
        │   ├── ...
        ├── generate_changelog.py
        └── changelog.md
        """,
        epilog="""\
        Usage example:

        python3 generate_changelog.py --out-version "v1.0.1" --out-series-name "Šaltibarščiai"

        Usage example when this script is inside a directory and the changelog and unreleased dir are one level above this script:

        python3 generate_changelog.py --out-version "v1.0.1" --out-series-name "Šaltibarščiai" --unreleased-dir "../.unreleased" --out-file "../changelog.md"

        Usage example without writing to the changelog or deleting the files in the unreleased dir:

        python3 generate_changelog.py --out-version "v1.0.1" --out-series-name "Šaltibarščiai" --dry-run
        """,
        formatter_class=argparse.RawTextHelpFormatter,
    )
    parser.add_argument(
        "--test",
        action="store_true",
        help="Runs unit tests and exit",
    )
    parser.add_argument(
        "--out-version",
        type=str,
        required=False,
        help="Output version number in text format.",
    )
    parser.add_argument(
        "--out-series-name",
        type=str,
        help="""Series version name of the output version in text format.
Defaults to empty if not provided.""",
    )
    parser.add_argument(
        "--unreleased-dir",
        type=str,
        default="../.unreleased",
        help="Path pointing into the .unreleased directory (path must be relative to this script).",
    )
    parser.add_argument(
        "--out-file",
        type=str,
        default="../changelog.md",
        help="Path to file into which to insert the changelog entries (path must be relative to this script).",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show the changes without writing them to the changelog file.",
    )
    parser.add_argument(
        "--no-delete",
        action="store_true",
        help="Write the changelog but keep the .unreleased files (deletion handled elsewhere).",
    )

    args = parser.parse_args()
    if not args.test and args.out_version is None:
        parser.error(
            "the argument --out-version is **required** when --test is not passed."
        )

    return args


def generate_changelog(
    unreleased_dir: str,
    out_version: str,
    out_series_name: Optional[str],
    out_file: str,
    dry_run: bool,
    no_delete: bool = False,
) -> int:
    """Main function for handling the changelog generation."""

    out_series_name = "" if out_series_name is None else out_series_name

    delete_files = not dry_run and not no_delete
    block = gather_output(unreleased_dir, out_version, out_series_name, delete_files)

    if dry_run:
        print(block)
        return 0

    if block is not None:
        insert_block_into_file(out_file, block, out_version)
    return 0


def test() -> int:
    """Testing ticket variations, that regex should match."""

    success = 0

    ticket_cases = [
        ("NMACOS-8047_blah_blah", "NMACOS-8047"),
        ("hwin_22222_sth_sth", "HWIN-22222"),
        ("NMACOS_2222 dgsdg", "NMACOS-2222"),
        ("P-999999-end", "P-999999"),
        ("PRO-JECT12_invalid_match", None),
        ("LLT-01234_", "LLT-01234"),
        ("llt_01234", "LLT-01234"),
        ("llt-1234-a", "LLT-1234"),
        ("LLT-1234", "LLT-1234"),
        ("LlT-01", "LLT-01"),
        ("lLt 01", "LLT-01"),
        ("bad-pattern", None),
        ("LLT 99", "LLT-99"),
        ("P-999999 ", "P-999999"),
    ]
    for text in ticket_cases:
        res = _match_ticket(text[0])
        if res == text[1]:
            print(f"Success for: {text[0]}")
        else:
            print(f"Failed for: {text[0]}, expected: {text[1]}, got: {res}")
            success = 1

    # Sorted insertion: v6.2.4 must land above v6.2.3, below v7.0.0 (a naive prepend fails this).
    body = (
        "### v8.0.0-rc1\n### ****\n---\n* a\n\n<br>\n\n"
        "### v7.0.0\n### ****\n---\n* b\n\n<br>\n\n"
        "### v6.2.3\n### ****\n---\n* c\n\n<br>\n\n"
    )
    block = "### v6.2.4\n### ****\n---\n* d\n\n<br>\n\n"
    result = insert_block_sorted(body, block, "v6.2.4")
    order = [v for v, _ in _version_headings(result)]
    if order == ["v8.0.0-rc1", "v7.0.0", "v6.2.4", "v6.2.3"]:
        print("Success insertion: v6.2.4 placed between v7.0.0 and v6.2.3")
    else:
        print(f"Failed insertion: got order {order}")
        success = 1

    # Idempotency: re-inserting an existing version replaces it in place (no duplicate).
    again = insert_block_sorted(result, block, "v6.2.4")
    order_again = [v for v, _ in _version_headings(again)]
    if again == result and order_again.count("v6.2.4") == 1:
        print("Success idempotency: re-inserting v6.2.4 does not duplicate")
    else:
        print(f"Failed idempotency: got order {order_again}")
        success = 1

    # The oldest version appends at the bottom (the fall-through branch).
    bottom = [
        v
        for v, _ in _version_headings(
            insert_block_sorted(body, "### v1.0.0\n---\n\n<br>\n\n", "v1.0.0")
        )
    ]
    if bottom[-1] != "v1.0.0":
        print(f"Failed insertion: lowest not at bottom, got {bottom}")
        success = 1

    # A '### vX.Y.Z' inside a fenced code block is not a real heading: the parser
    # must ignore it (a line regex would wrongly treat it as a version boundary).
    code_body = (
        "### v8.0.0\n### ****\n---\n* real entry\n\n"
        "```\n### v9.9.9\n```\n\n<br>\n\n"
        "### v6.2.3\n### ****\n---\n* c\n\n<br>\n\n"
    )
    code_order = [
        v
        for v, _ in _version_headings(
            insert_block_sorted(code_body, "### v7.0.0\n---\n\n<br>\n\n", "v7.0.0")
        )
    ]
    if code_order == ["v8.0.0", "v7.0.0", "v6.2.3"]:
        print("Success code-fence: fake '### v9.9.9' in a code block is ignored")
    else:
        print(f"Failed code-fence: got order {code_order}")
        success = 1

    # A missing .unreleased dir means no entries, not an error.
    if gather_output("/nonexistent/.unreleased", "v1.0.0", "", False) is None:
        print("Success: missing .unreleased dir -> no entries")
    else:
        print("Failed: missing .unreleased dir should return None")
        success = 1

    return success


if __name__ == "__main__":
    # Get the directory where the script is located
    script_dir = os.path.dirname(os.path.abspath(__file__))
    # Change the working directory
    os.chdir(script_dir)

    args = parse_args()
    sys.exit(
        generate_changelog(
            args.unreleased_dir,
            args.out_version,
            args.out_series_name,
            args.out_file,
            args.dry_run,
            args.no_delete,
        )
        if not args.test
        else test()
    )
