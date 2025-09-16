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
from typing import Optional

from vessel.diff.helpers.failure import Failure, FailureSummary
from vessel.diff.helpers.flag import Flag
from vessel.diff.helpers.file_diff import FileDiff, FileDiffs
from vessel.utils.flag_check import check_flags
from vessel.utils.unified_diff import (
    intervals_to_str,
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
    diff_list: FileDiffs,
) -> dict[tuple[str, str], FileDiffs]:
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

    lookup: dict[tuple[str, str], FileDiffs] = {}
    for diff in diff_list.diffs:
        key = (
            relative_path_after_rootfs(diff.source1),
            relative_path_after_rootfs(diff.source2),
        )
        if key not in lookup:
            lookup[key] = FileDiffs()
        lookup[key].diffs.append(diff)

    return lookup


class DiffoscopeParser:
    """Class to parse Diffoscope output."""

    def __init__(
        self: "DiffoscopeParser",
        diffoscope_json: dict,
        flags: list[Flag],
        filetype_lookup1: Optional[dict[str, str]] = None,
        filetype_lookup2: Optional[dict[str, str]] = None,
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

        self.failure_summary = FailureSummary()
        self.diff_list: FileDiffs = FileDiffs()

        self._recurse(self.diffoscope_json)
        self.failure_summary.calculate_aggregated_values()

    def _recurse(
        self: "DiffoscopeParser",
        detail: dict,
        parent_source1: str = "",
        parent_source2: str = "",
        parent_comments: Optional[list[str]] = None,
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
        parent_comments: Optional[list[str]] = None,
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

        file_diff = FileDiff(
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
            file_diff.command = detail["source1"]
            file_diff.source1 = parent_source1
            file_diff.source2 = parent_source2

        is_binary = bool(detail.get("has_internal_linenos"))
        for minus_line, plus_line in zip(
            file_diff.minus_aligned_lines,
            file_diff.plus_aligned_lines,
            strict=False,
        ):
            failure_summary, flagged_failure_list, unknown_failure_list = check_flags(self.flags, self.filetype_lookup1, self.filetype_lookup2, file_diff, minus_line, plus_line, is_binary)
            self.failure_summary.unknown_failures += failure_summary.unknown_failures
            self.failure_summary.trivial_failures += failure_summary.trivial_failures
            self.failure_summary.nontrivial_failures += failure_summary.nontrivial_failures
            file_diff.flagged_failures = flagged_failure_list
            file_diff.unknown_failures = unknown_failure_list

            # Check so line by line comparison don't happen in binary diffs and
            # this is after all the flags have been checked so the diff is done
            # being evaluated
            if is_binary:
                if len(file_diff.flagged_failures) == 0:
                    self.unknown_failure_count += 1
                    file_diff.unknown_failures.append(
                        Failure(comments=[
                            "Flag indiff regex are not ran on binary "
                            "unified diff. This file did not match any "
                            "flags.",
                        ])
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
                file_diff.unknown_failures.append(
                    Failure(
                        minus_line if minus_line else None,
                        plus_line if plus_line else None,
                        minus_unmatched_str,
                        plus_unmatched_str
                    ),
                )

        self.diff_list.diffs.append(file_diff)
