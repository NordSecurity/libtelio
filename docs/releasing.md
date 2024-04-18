# Releasing Libtelio

This file documents the release process of libtelio.

## The Release Script

To prepare a release, there's a helper script `release.py`. This script will tag the commit and change versions in all relevant places.

The common usage is:
```
release.py --changelog --push --tag=v4.0.5
```

You can check the actual commands executed, by passing the `--dry-run` argument.

## Changelog Generation

If you don't want to use the `release.py` script, you'll need to manually generate the `changelog.md` using the `ci/generate_changelog.py` script.

This script will take all the content from each file in the `.unreleased` directory, add it to the changelog and delete those files. The unreleased change descriptions are kept in separate files to avoid merge conflicts on the `changelog.md` file on PRs.

You can use `generate_changelog.py --help` to find out more about the usage of the script. For this specific project structure example, the script arguments would be:

```
python3 ci/generate_changelog.py --out_version "v1.2.3" --out-series_name "Šaltibarščiai" --unreleased-dir ".unreleased" --out-file "changelog.md"
```

- `v1.2.3` is the version of the release being made. This value is required.
- `Šaltibarščiai` is the series version name (like android lollipop). If omitted, the last series version name will be used.
- `.unreleased` is the directory containing all the new unreleased change descriptions. Default is ".unreleased"
- `changelog.md` is the actual changelog onto which the changelog entries will be prepended. Default is "changelog.md"

If you're not sure about running the script and want to check the output before writing or deleting any files, you can use `generate_changelog.py --dry-run`

>NOTE: In case there are entries in the changelog file that need to be converted into unreleased change files, you can use this one liner:

```
tail -n +4 ../changelog.md | head -n <number_of_entries_to_extract + 1> | sed -E 's/\* (LLT-[0-9][0-9][0-9][0-9]): (.*)/\1 \"\2\"/' | xargs -n2 sh -c 'echo "$2" >> $1' sh
```

