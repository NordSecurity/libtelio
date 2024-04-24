"""OS module for file operations,
argparse module for command line arguments parsing,
sys module for graceful exiting,
regex for searching for old series name. re is does not support unicode characters,
Optional for optional type."""

import os
import sys
import argparse
from typing import Optional
import regex


# Regex used to find the previous version.
PREVIOUS_VERSION_REGEX = r"^###.+\n"
# Regex for finding the series name right after the last version entry.
SERIES_NAME_REGEX = r"^### \*\*([\p{L}]+)\*\*$"

# Python automatically translates the '\n' escape character for cross platform compatibility.
# Format use to print the version at the beginning of the new version entry in the changelog.
HEADER_FORMAT = "### {}\n### **{}**\n---\n"
# Format for actual every version entry.
ENTRY_FORMAT = "* {}: {}\n"
# Format use to print the ending of the new version entry in the changelog.
VERSION_ENDING = "\n<br>\n\n"

# A line at the top of the changelog file to indicate that it's auto-generated.
AUTO_GENERATION_NOTE_LINE = (
    "<!-- Note: this file is auto-generated. See CONTRIBUTING.md for details. -->\n\n"
)


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
        "--out-version",
        type=str,
        required=True,
        help="Output version number in text format.",
    )
    parser.add_argument(
        "--out-series-name",
        type=str,
        help="""Series version name of the output version in text format.
Will try to find the previous series name if not provided.""",
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
        help="Path to file into which to prepend the changelog entries (path must be relative to this script).",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show the changes without prepending them to the changelog file.",
    )

    return parser.parse_args()


def get_old_series_name(out_file: str) -> str:
    """Function that finds and returns the old series name of the previous version
    so that it can be used as the default value.

    Args:
        out_file (str): Path to the changelog.md file.

    Returns:
        str: The old series name.
    """

    series_name = ""

    with open(out_file, "r", encoding="utf-8") as changelog_file:
        old_entries = changelog_file.read()
        match = regex.search(PREVIOUS_VERSION_REGEX, old_entries)
        if match:
            line_after_version = old_entries[match.end() :].splitlines()[0]
            match = regex.search(SERIES_NAME_REGEX, line_after_version)
            if match:
                series_name = match.group() + "\n"

    return series_name


def gather_output(
    unreleased_dir: str, out_version: str, out_series_name: str, dry_run: bool
) -> Optional[str]:
    """Function that handles gathering all the changelog entries from the unreleased dir
    into a string. Returns None, if there are no entries.

    Args:
        unreleased_dir (str):   path into (and including) .unreleased directory where all the
                                files with the change descriptions are stored.
        out_version (str):      Version of the release that's being made.
        out_series_name (str):  Version series name (like android lollipop).
        dry_run (bool):         Only show the changes that would be made and don't write to
                                or delete any files.

    Returns:
        Optional[str]: The aggregated entries including the header and footer to
                       prepend to the changelog file.
    """

    # The following bool is used to prevent unwanted behavior
    # when no version entries are present in the new version directory.
    at_least_one_entry_found = False

    output = HEADER_FORMAT.format(out_version, out_series_name)

    for changelog_entry_file in os.scandir(unreleased_dir):
        with open(changelog_entry_file, "r", encoding="utf-8") as changelog_entry_file:
            for line in changelog_entry_file.readlines():
                at_least_one_entry_found = True
                entry_ticket_id = os.path.basename(changelog_entry_file.name)
                output += ENTRY_FORMAT.format(entry_ticket_id, line.strip())
        if not dry_run:
            os.remove(changelog_entry_file.name)
    output += VERSION_ENDING

    return output if at_least_one_entry_found else None


def generate_changelog(
    unreleased_dir: str,
    out_version: str,
    out_series_name: Optional[str],
    out_file: str,
    dry_run: bool,
) -> int:
    """Main function for handling the changelog generation."""

    out_series_name = (
        get_old_series_name(out_file) if out_series_name is None else out_series_name
    )

    output = gather_output(unreleased_dir, out_version, out_series_name, dry_run)

    with open(out_file, "r", encoding="utf-8") as changelog_file:
        next(changelog_file)  # Discarding the note that this file is autogenerated.
        next(changelog_file)  # Discarding the newline.
        old_entries = changelog_file.read()

    if not dry_run:
        if output is not None:
            with open(out_file, "w", encoding="utf-8") as changelog_file:
                changelog_file.write(AUTO_GENERATION_NOTE_LINE + output + old_entries)
    else:
        print(output)
    return 0


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
        )
    )
