# Vessel Diff Tool
#
# Copyright 2024 Carnegie Mellon University.
#
# NO WARRANTY. THIS CARNEGIE MELLON UNIVERSITY AND SOFTWARE ENGINEERING
# INSTITUTE MATERIAL IS FURNISHED ON AN "AS-IS" BASIS. CARNEGIE MELLON
# UNIVERSITY MAKES NO WARRANTIES OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
# AS TO ANY MATTER INCLUDING, BUT NOT LIMITED TO, WARRANTY OF FITNESS
# FOR PURPOSE OR MERCHANTABILITY, EXCLUSIVITY, OR RESULTS OBTAINED FROM
# USE OF THE MATERIAL. CARNEGIE MELLON UNIVERSITY DOES NOT MAKE ANY
# WARRANTY OF ANY KIND WITH RESPECT TO FREEDOM FROM PATENT, TRADEMARK,
# OR COPYRIGHT INFRINGEMENT.
#
# Licensed under a MIT (SEI)-style license, please see license.txt
# or contact permission@sei.cmu.edu for full terms.
#
# [DISTRIBUTION STATEMENT A] This material has been approved for public
# release and unlimited distribution.  Please see Copyright notice
# for non-US Government use and distribution.
#
# This Software includes and/or makes use of Third-Party Software
# each subject to its own license.
#
# DM24-1321

"""Utility Diffoscope functions."""

import re
from pathlib import Path
from typing import Any

import magic

from vessel.utils.flag import Flag
from vessel.utils.unified_diff import (
    Diff,
    DiffLine,
    failures_from_difflines,
    intervals_to_str,
    make_failure_dict,
)


def build_diffoscope_command(
    output_dir_path: str,
    output_file_name: str,
    path1: str,
    path2: str,
    mode: str,
    profile_enabled: bool,
) -> list[str]:
    """Generates a command list to execute diffoscope.

    Args:
        output_dir_path: Path to directory that Diffoscope JSON output will be
            written to
        output_file_name: File name that will be used for diffoscope output
        path1: The first path to compare
        path2: The second path to compare
        mode: Comparison mode ("image" or "file")
        profile_enabled: If True, append '--profile <output_dir_path>/profile.txt'

    Returns:
        Commands list to execute diffoscope.
    """
    cmd = ["diffoscope"]
    cmd.extend(["--json", f"{output_dir_path}/{output_file_name}"])

    if mode == "file":
        cmd.append("--new-file")

    cmd.extend([path1, path2])
    cmd.extend(["--exclude-directory-metadata", "no"])
    if profile_enabled:
        cmd.extend(["--profile", f"{output_dir_path}/profile.txt"])
    exclude_patterns = [
        r"^readelf.*",
        r"^objdump.*",
        r"^strings.*",
        r"^xxd.*",
    ]
    for pattern in exclude_patterns:
        cmd.extend(["--exclude-command", pattern])
    return cmd


def build_diff_lookup(
    diff_list: list[dict[str, Any]],
) -> dict[tuple[str, str], list[dict[str, Any]]]:
    """Build a lookup dictionary for diff results, keyed by (relative_path1, relative_path2).

    Args:
        diff_list: List of all diffs from parsed diffoscope output

    Returns:
        Dict keyed with a tuple of paths relative to 'rootfs' directory, and value
        all of the diffs detected by diffoscope for those paths
    """

    def relative_path_after_rootfs(path):
        """Return path relative to rootfs with rootfs stripped out."""
        idx = path.rfind("rootfs/")
        if idx != -1:
            return path[idx + len("rootfs/") :]
        return path

    lookup: dict[Any, Any] = {}
    for diff in diff_list:
        key = (
            relative_path_after_rootfs(diff["source1"]),
            relative_path_after_rootfs(diff["source2"]),
        )
        if key not in lookup:
            lookup[key] = []
        lookup[key].append(diff)

    return lookup


class DiffoscopeParser:
    """Class to parse Diffoscope output."""

    def __init__(
        self: "DiffoscopeParser",
        diffoscope_json: dict,
        flags: list[Flag],
        filetype_lookup1: dict[str, str] | None = None,
        filetype_lookup2: dict[str, str] | None = None,
    ) -> None:
        """Initializer for Diffoscope parser.

        Initializes class varaibles and then executes parsing. Parses Diffoscope JSON and
        flags differences using flags. After execution, class variables will be populated for
        unknown, trivial and nontrivial failure counts and list of calculated diffs.

        Args:
            diffoscope_json: JSON from diffoscope representing all differences of two containers
            flags: List of flags used to flag differences as known failures
            filetype_lookup1: Optional lookup for filetypes of all files in source1. Used when
                in JSON mode and files being compared are not guaranteed to be accessible.
            filetype_lookup2: Optional lookup for filetypes of all files in source2. Used when
                in JSON mode and files being compared are not guaranteed to be accessible.
        """
        self.diffoscope_json: dict = diffoscope_json
        self.flags: list[Flag] = flags
        self.filetype_lookup1 = filetype_lookup1
        self.filetype_lookup2 = filetype_lookup2

        self.unknown_failure_count: int = 0
        self.trivial_failure_count: int = 0
        self.nontrivial_failure_count: int = 0
        self.diff_list: list[dict[str, Any]] = []

        self._recurse(self.diffoscope_json)

    def _recurse(
        self: "DiffoscopeParser",
        detail: dict,
        parent_source1: str = "",
        parent_source2: str = "",
        parent_comments: list[str] | None = None,
    ) -> None:
        """Handle recursion through all differences in diffoscope JSON object.

        Recursively navigates through entirety of diffoscope json output
        parsing the difference details.

        Args:
            detail: Dict object containing an instance of a difference
                from diffoscope output
            parent_source1: Source of difference of parent1 to substitute into
                source field if the source is a CLI tool and not a file name
            parent_source2: Source of difference of parent2 to substitute into
                source field if the source is a CLI tool and not a file name
            parent_comments: List of comments from the parent object in diffoscope
                as sometimes the comments that relate to a child are in
                the parent detail
        """
        umociRegex = re.compile(r"/umoci-unpack-")

        if detail["unified_diff"] is not None:
            self._parse_detail(
                detail, parent_source1, parent_source2, parent_comments
            )

        if "details" in detail:
            for child in detail["details"]:
                # Ignore anything without the umoci-unpack- path that shouldn't be showing in diffs
                if (
                    child["source1"][0] != "/"
                    or child["source2"][0] != "/"
                    or (
                        umociRegex.search(child["source1"])
                        and umociRegex.search(child["source2"])
                    )
                ):
                    self._recurse(
                        child,
                        detail["source1"],
                        detail["source2"],
                        detail.get("comments", None),
                    )

    def _parse_detail(
        self: "DiffoscopeParser",
        detail: dict,
        parent_source1: str = "",
        parent_source2: str = "",
        parent_comments: list[str] | None = None,
    ):
        """Parse one detail (one file difference) of the Diffoscope JSON.

        Checks the detail against all flags and appends the resulting diff
        to self.diff_list.

        Args:
            detail: Detail to be parsed
            parent_source1: Source1 of parent, used to populate source1 when diff is found with a command
            parent_source2: Source2 of parent, used to populate source2 when diff is found with a command
            parent_comments: Comments in parent, appended to comments for this diff

        """
        temp_comments = []
        if "comments" in detail:
            temp_comments.extend(detail["comments"])
        if parent_comments:
            temp_comments.extend(parent_comments)

        diff = Diff(
            detail["source1"],
            detail["source2"],
            temp_comments,
            detail["unified_diff"],
        )
        # Handles case where diff is found with a command such as stat {}.
        # Diffoscope lists the source of the diff as the command that it used to get
        # the diff, so the file path must be grabbed from the parent.
        if (
            not Path(detail["source1"]).is_absolute()
            or not Path(detail["source2"]).is_absolute()
        ):
            diff.command = detail["source1"]
            diff.source1 = parent_source1
            diff.source2 = parent_source2

        is_binary = bool(detail.get("has_internal_linenos"))
        for minus_line, plus_line in zip(
            diff.minus_aligned_lines,
            diff.plus_aligned_lines,
            strict=False,
        ):
            self._check_flags(diff, minus_line, plus_line, is_binary)

            # Check so line by line comparison don't happen in binary diffs and
            # this is after all the flags have been checked so the diff is done
            # being evaluated
            if is_binary:
                if len(diff.flagged_failures) == 0:
                    self.unknown_failure_count += 1
                    diff.unknown_failures.append(
                        {
                            "comments": [
                                "Flag indiff regex are not ran on binary "
                                "unified diff. This file did not match any "
                                "flags.",
                            ],
                        },
                    )

                break

            minus_unmatched_str = (
                intervals_to_str(
                    minus_line.text,
                    minus_line.unmatched_intervals,
                )
                if minus_line
                else None
            )
            plus_unmatched_str = (
                intervals_to_str(
                    plus_line.text,
                    plus_line.unmatched_intervals,
                )
                if plus_line
                else None
            )
            if minus_unmatched_str != plus_unmatched_str:
                self.unknown_failure_count += 1
                diff.unknown_failures.append(
                    make_failure_dict(
                        minus_line if minus_line else None,
                        plus_line if plus_line else None,
                        minus_unmatched_str,
                        plus_unmatched_str,
                    ),
                )

        self.diff_list.append(diff.to_slim_dict())

    def _check_flags(
        self: "DiffoscopeParser",
        diff: Diff,
        minus_line: DiffLine,
        plus_line: DiffLine,
        is_binary: bool,
    ):
        """Check a Diff against all flags and update Diff based on matches or non matches.

        Take in a Diff, iterate through all of the flags and check if each matches the difference and
        the minus and plus lines of the Diff while updating the failure counts, and the lists of
        failures in the Diff parameter object.

        Args:
            diff: Diff object to be checked
            minus_line: Line of the minus file in the unified diff to be checked
            plus_line: Line of the plus file in the unified diff to be checked
        """
        for flag in self.flags:
            flag_matches = True

            # Check if filepath matches flag
            flag_matches = self._check_flag_filepath(
                flag, diff.source1, diff.source2
            )

            # Check if filetype matches flag
            if flag_matches:
                flag_matches = self._check_flag_filetype(
                    flag, diff.source1, diff.source2
                )

            # Check if command matches flag
            if flag_matches:
                flag_matches = self._check_flag_command(flag, diff.command)

            # Check if comment matches flag
            if flag_matches:
                flag_matches = self._check_flag_comment(flag, diff.comments)

            # Handle a binary line that matches the flag
            if (
                flag_matches
                and is_binary
                and flag.regex["indiff"] == re.compile(".*")
            ):
                diff.flagged_failures.append(
                    {
                        "id": flag.flag_id,
                        "description": flag.description,
                        "metadata": getattr(flag, "metadata", False),
                        "comments": [
                            "Flag indiff regex are not ran on binary "
                            "unified diff. However this matched all "
                            "of the other criteria for this flag.",
                        ],
                    },
                )
            # Handle any non-binary line that matches the flag
            elif flag_matches:
                (
                    flagged_failure_list,
                    unknown_failure_list,
                    minus_line.unmatched_intervals,
                    plus_line.unmatched_intervals,
                ) = failures_from_difflines(
                    minus_line,
                    plus_line,
                    flag,
                )
                # Check to not create duplicate matches on flags that match based on filepath, filetype, command or comment
                #     and have indiff set to ".*"
                if flag.regex["indiff"] != re.compile(
                    ".*"
                ) or flag.flag_id not in [
                    flag["id"] for flag in diff.flagged_failures
                ]:
                    for failure in flagged_failure_list:
                        failure["metadata"] = flag.metadata
                        failure["severity"] = flag.severity
                        if flag.severity == "Low":
                            self.trivial_failure_count += 1
                        else:
                            self.nontrivial_failure_count += 1
                    self.unknown_failure_count += len(unknown_failure_list)
                    diff.flagged_failures.extend(flagged_failure_list)
                    diff.unknown_failures.extend(unknown_failure_list)

    def _check_flag_filepath(
        self: "DiffoscopeParser", flag: Flag, source1: str, source2: str
    ) -> bool:
        """Check difference sources against filepath regex of flag.

        Args:
            flag: Flag to check against
            source1: String representing filepath to source1
            source2: String representing filepath to source2
        """
        if not flag.regex["filepath"].search(source1) or not flag.regex[
            "filepath"
        ].search(source2):
            return False
        else:
            return True

    def _check_flag_filetype(
        self: "DiffoscopeParser", flag: Flag, source1: str, source2: str
    ) -> bool:
        """Check difference sources against filetype regex of flag.

        Perform check of source filetypes. If both files exist locally, use
        magic library for data type otherwise use types from the metadata.

        Args:
            flag: Flag to check against
            source1: String representing filepath to source1
            source2: String representing filepath to source2
        """
        source_1_exists = Path(source1).is_file()
        source_2_exists = Path(source2).is_file()
        if source_1_exists and source_2_exists:
            file_type_1 = magic.from_file(source1)
            file_type_2 = magic.from_file(source2)
            if not flag.regex["filetype"].search(
                file_type_1
            ) or not flag.regex["filetype"].search(file_type_2):
                return False
        else:
            # Local file does not exist: try checksum metadata lookups.
            if (
                self.filetype_lookup1 is not None
                and self.filetype_lookup2 is not None
            ):
                file_type_1 = self.filetype_lookup1.get(source1, "")
                file_type_2 = self.filetype_lookup2.get(source2, "")

                if file_type_1 and file_type_2:
                    if not flag.regex["filetype"].search(
                        file_type_1
                    ) or not flag.regex["filetype"].search(file_type_2):
                        return False

        return True

    def _check_flag_command(
        self: "DiffoscopeParser", flag: Flag, command: str
    ) -> bool:
        """Check difference command against command regex of flag.

        Command of the difference will be populated if the diff was found by diffoscope
        using a command such as stat {}.

        Args:
            flag: Flag to check against
            command: Command used to find diff
        """
        if not flag.regex["command"].search(command):
            return False
        else:
            return True

    def _check_flag_comment(
        self: "DiffoscopeParser", flag: Flag, comments: list
    ) -> bool:
        """Check difference comments against comment regex of flag.

        Checks if any comment of the command matches, or if the comment list is
        empty and the regex is set to accept any value.
        """
        if comments != [] and not any(
            flag.regex["comment"].search(comment) for comment in comments
        ):
            return False
        elif comments == [] and flag.regex["comment"] != re.compile(".*"):
            return False
        else:
            return True
