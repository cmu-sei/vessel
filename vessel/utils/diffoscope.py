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
from logging import getLogger
from pathlib import Path
from typing import Any

import magic

from vessel.utils.flag import Flag
from vessel.utils.unified_diff import (
    Diff,
    failures_from_difflines,
    intervals_to_str,
    make_failure_dict,
)

logger = getLogger(__name__)


def build_diffoscope_command(
    output_dir_path: str,
    output_file_name: str,
    path1: str,
    path2: str,
    compare_level: str,
) -> list[str]:
    """Generates a command list to execute diffoscope.

    Args:
        output_dir_path: Path to directory that Diffoscope json output will be
            written to
        output_file_name: File name that will be used for diffoscope output
        path1: The first path to compare
        path2: The second path to compare
        compare_level: Diff mode (image or file)

    Returns:
        Commands list to execute diffoscope.
    """
    cmd = ["diffoscope"]
    cmd.extend(["--json", f"{output_dir_path}/{output_file_name}"])

    if compare_level == "file":
        cmd.append("--new-file")

    cmd.extend([path1, path2])
    cmd.extend(["--exclude-directory-metadata", "no"])
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


def _is_path(source_string: object) -> bool:
    """True if source tring is a path that starts with leading /"""
    return isinstance(source_string, str) and source_string.startswith("/")


def parse_diffoscope_output(
    current_detail: dict,
    flags: list[Flag],
    parent_source1: str = "",
    parent_source2: str = "",
    parent_comments: list[str] | None = None,
    filetype_lookup1=None,
    filetype_lookup2=None,
) -> tuple[int, int, int, list[dict[Any, Any]]]:
    """Recursively parses diffoscope json output

    Recursively navigates through entirety of diffoscope json output
    parsing the diffs and returning a JSON object with failures
    flagged based on contents of `config/diff_config.yaml`

    Args:
        current_detail: Dict object containing an instance of a diff
                        from diffoscope output
        flags: List of all flags contained within
                `config/diff_config.yaml`
        parent_source1: Source of diff of parent1 to substitute into
                        source field if the source is a CLI tool and
                        not a file name
        parent_source2: Source of diff of parent2 to substitute into
                        source field if the source is a CLI tool and
                        not a file name
        parent_comments: List of comments from the parent object in diffoscope
                        as sometimes the comments that relate to a child are in
                        the parent detail
    Returns:
        Count of unknown failures, count of flagged failures, diff list,
        and overall file analysis summary
    """
    trivial_failures_count = 0
    nontrivial_failures_count = 0
    unknown_failures_count = 0
    diff_list = []

    if current_detail["unified_diff"] is not None:
        temp_comments = []
        if "comments" in current_detail:
            temp_comments.extend(current_detail["comments"])
        if parent_comments:
            temp_comments.extend(parent_comments)

        diff = Diff(
            current_detail["source1"],
            current_detail["source2"],
            parent_source1,
            parent_source2,
            temp_comments,
            current_detail["unified_diff"],
        )

        # Handles case where diff is found with a command such as stat {}.
        # Diffoscope lists the source of the diff as the command that it used to get
        # the diff, so the file path must be grabbed from the parent.
        source1_raw = str(current_detail.get("source1", ""))
        source2_raw = str(current_detail.get("source2", ""))

        if not _is_path(source1_raw) or not _is_path(source1_raw):
            diff.command = source2_raw
            diff.source1 = parent_source1
            diff.source2 = parent_source2

        # Initialize to False to ensure one iteration through the flags.
        # If it then is found to be binary, the rest of the lines
        # will not be evaluated to not check binary line by line.
        is_binary = False
        for minus_line, plus_line in zip(
            diff.minus_aligned_lines,
            diff.plus_aligned_lines,
            strict=False,
        ):
            is_binary = bool(current_detail.get("has_internal_linenos"))
            for flag in flags:
                flag_matches = True
                file_type_1 = ""
                file_type_2 = ""
                # Check if filepath matches flag
                if not flag.regex["filepath"].search(
                    diff.source1,
                ) or not flag.regex["filepath"].search(
                    diff.source2,
                ):
                    flag_matches = False

                #  - If both files exist locally, use magic library for data type.
                #  - Else, use types from the metadata.
                if flag_matches:
                    source_1_exists = Path(diff.source1).is_file()
                    source_2_exists = Path(diff.source2).is_file()
                    if source_1_exists and source_2_exists:
                        file_type_1 = magic.from_file(diff.source1)
                        file_type_2 = magic.from_file(diff.source2)
                        if not flag.regex["filetype"].search(
                            file_type_1
                        ) or not flag.regex["filetype"].search(file_type_2):
                            flag_matches = False
                    else:
                        # Local file does not exist: try checksum metadata lookups.
                        if (
                            filetype_lookup1 is not None
                            and filetype_lookup2 is not None
                        ):
                            rel1 = diff.source1
                            rel2 = diff.source2
                            file_type_1 = (filetype_lookup1 or {}).get(
                                rel1, ""
                            )
                            file_type_2 = (filetype_lookup2 or {}).get(
                                rel2, ""
                            )

                            if file_type_1 and file_type_2:
                                if not flag.regex["filetype"].search(
                                    file_type_1
                                ) or not flag.regex["filetype"].search(
                                    file_type_2
                                ):
                                    flag_matches = False

                # Check if command matches flag
                if flag_matches and not flag.regex["command"].search(
                    diff.command
                ):
                    flag_matches = False

                # Check if comment matches flag
                if flag_matches and (
                    (
                        diff.comments != []
                        and not any(
                            flag.regex["comment"].search(comment) 
                            for comment in diff.comments
                        )
                    )
                    or (
                        diff.comments == []
                        and flag.regex["comment"] != re.compile(".*")
                    )
                ):  # fmt: skip
                    flag_matches = False

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
                            failure["metadata"] = getattr(
                                flag, "metadata", False
                            )
                            failure["severity"] = getattr(
                                flag, "severity", "Low"
                            )
                            if getattr(flag, "severity") == "Low":
                                trivial_failures_count += 1
                            else:
                                nontrivial_failures_count += 1
                        unknown_failures_count += len(unknown_failure_list)
                        diff.flagged_failures.extend(flagged_failure_list)
                        diff.unknown_failures.extend(unknown_failure_list)

            # Check so line by line comparison don't happen in binary diffs and
            # this is after all the flags have been checked so the diff is done
            # being evaluated
            if is_binary:
                if len(diff.flagged_failures) == 0:
                    unknown_failures_count += 1
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
                unknown_failures_count += 1
                diff.unknown_failures.append(
                    make_failure_dict(
                        minus_line if minus_line else None,
                        plus_line if plus_line else None,
                        minus_unmatched_str,
                        plus_unmatched_str,
                    ),
                )

        diff_list.append(diff.to_slim_dict())

    # Recurvisely navigating through the tree
    if "details" in current_detail:
        umociRegex = re.compile(r"/umoci-unpack-")

        for child in current_detail["details"]:
            # Ignore anything without the umoci-unpack- path that shouldn't be showing in diffs
            if (
                child["source1"][0] != "/"
                or child["source2"][0] != "/"
                or umociRegex.search(child["source1"])
                or umociRegex.search(child["source2"])
            ):
                child_return = parse_diffoscope_output(
                    child,
                    flags,
                    current_detail["source1"],
                    current_detail["source2"],
                    current_detail.get("comments"),
                    filetype_lookup1=filetype_lookup1,
                    filetype_lookup2=filetype_lookup2,
                )
                unknown_failures_count += child_return[0]
                trivial_failures_count += child_return[1]
                nontrivial_failures_count += child_return[2]
                diff_list.extend(child_return[3])

        return (
            unknown_failures_count,
            trivial_failures_count,
            nontrivial_failures_count,
            diff_list,
        )

    return (
        unknown_failures_count,
        trivial_failures_count,
        nontrivial_failures_count,
        diff_list,
    )
