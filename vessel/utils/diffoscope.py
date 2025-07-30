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
from typing import Any, Optional

import magic

from vessel.utils.checksum import (
    classify_checksum_mismatches,
    hash_folder_contents,
    summarize_checksums,
)
from vessel.utils.flag import Flag
from vessel.utils.unified_diff import (
    Diff,
    intervals_to_str,
    issues_from_difflines,
    make_issue_dict,
)


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
    """
    Build a lookup dictionary for diff results, keyed by (relative_path, relative_path).

    Each key is a tuple of paths relative to the 'rootfs/' directory,
    with the 'rootfs/' prefix removed from both source paths.
    """

    def relative_path_after_rootfs(path):
        """Return path relative to rootfs with rootfs stripped out."""
        idx = path.rfind("rootfs/")
        if idx != -1:
            return path[idx + len("rootfs/") :]
        return path

    lookup: dict[Any, Any] = {}
    for d in diff_list:
        relative_path = relative_path_after_rootfs(d["source1"])
        key = (relative_path, relative_path)
        if key not in lookup:
            lookup[key] = []
        lookup[key].append(d)

    return lookup


def parse_diffoscope_output(
    current_detail: dict,
    flags: list[Flag],
    parent_source1: str = "",
    parent_source2: str = "",
    parent_comments: list[str] | None = None,
    files_summary: Optional[list[dict[str, Any]]] = None,
    file_checksum: bool = False,
) -> tuple[
    int, int, int, list[dict[Any, Any]], list[dict[str, Any]], dict[Any, Any]
]:
    """Recursively parses diffoscope json output.

    Recursively navigates through entirety of diffoscope json output
    parsing the diffs and returning a JSON object with issues
    flagged based on contents of `config/diff_config.yaml`

    Args:
        current_detail: Dict object containing an instance of a diff
                        from diffoscope output.
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
        files_summary: File analysis of trivial/nontrivial issue
        file_checksum: Whether detail of checksum matches and mismatch
                       should be included in the summary.json

    Returns:
        Count of unknown issues, count of flagged issues, diff list,
        and overall file analysis summary and checksum comparison summary.
    """
    trivial_issues_count = 0
    nontrivial_issues_count = 0
    unknown_issues_count = 0
    diff_list = []

    if files_summary is None:
        files_summary = []

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
        if (
            not Path(diff.source1).is_file()
            and not Path(diff.source2).is_file()
        ):
            diff.command = current_detail["source1"]
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

                # Check if filetype matches flag
                if (
                    flag_matches
                    and Path(diff.source1).is_file()
                    and Path(diff.source2).is_file()
                ):
                    file_type_1 = magic.from_file(
                        diff.source1,
                    )
                    file_type_2 = magic.from_file(
                        diff.source2,
                    )

                    if not flag.regex["filetype"].search(
                        file_type_1,
                    ) or not flag.regex["filetype"].search(file_type_2):
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
                    diff.flagged_issues.append(
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
                        flagged_issue_list,
                        unknown_issue_list,
                        minus_line.unmatched_intervals,
                        plus_line.unmatched_intervals,
                    ) = issues_from_difflines(
                        minus_line,
                        plus_line,
                        flag,
                    )
                    # Check to not create duplicate matches on flags that match based on filepath, filetype, command or comment
                    #     and have indiff set to ".*"
                    if flag.regex["indiff"] != re.compile(
                        ".*"
                    ) or flag.flag_id not in [
                        flag["id"] for flag in diff.flagged_issues
                    ]:
                        for issue in flagged_issue_list:
                            issue["metadata"] = getattr(
                                flag, "metadata", False
                            )
                            if getattr(flag, "severity") == "Low":
                                trivial_issues_count += 1
                            else:
                                nontrivial_issues_count += 1
                        unknown_issues_count += len(unknown_issue_list)
                        diff.flagged_issues.extend(flagged_issue_list)
                        diff.unknown_issues.extend(unknown_issue_list)

            # Check so line by line comparison don't happen in binary diffs and
            # this is after all the flags have been checked so the diff is done
            # being evaluated
            if is_binary:
                if len(diff.flagged_issues) == 0:
                    unknown_issues_count += 1
                    diff.unknown_issues.append(
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
                unknown_issues_count += 1
                diff.unknown_issues.append(
                    make_issue_dict(
                        minus_line if minus_line else None,
                        plus_line if plus_line else None,
                        minus_unmatched_str,
                        plus_unmatched_str,
                    ),
                )

        diff_list.append(diff.to_slim_dict())

    # Recurvisely navigating through the tree
    if "details" in current_detail:
        for child in current_detail["details"]:
            # Ignore anything without our full /tmp/diffoscope path that shouldn't be showing in diffs
            if not re.compile(r"/tmp/diffoscope_*").search(child["source1"]) and not re.compile(r"/tmp/diffoscope_*").search(child["source2"]):
                child_return = parse_diffoscope_output(
                    child,
                    flags,
                    umoci_image_paths,
                    current_detail["source1"],
                    current_detail["source2"],
                    current_detail.get("comments"),
                    files_summary,
                    file_checksum=file_checksum,
                )
                unknown_issues_count += child_return[0]
                trivial_issues_count += child_return[1]
                nontrivial_issues_count += child_return[2]
                diff_list.extend(child_return[3])

    checksum_summary = {}
    # Only generate the final summary when it's top-level call (end of recursion)
    if (
        parent_source1 == ""
        and parent_source2 == ""
        and parent_comments is None
    ):
        # Path to rootfs of unpacked image, ex: image1/rootfs
        rootfs_path1 = Path(current_detail["source1"])
        rootfs_path2 = Path(current_detail["source2"])
        hashed_files1 = hash_folder_contents(rootfs_path1)
        hashed_files2 = hash_folder_contents(rootfs_path2)
        files1 = {str(filehash.path): filehash for filehash in hashed_files1}
        files2 = {str(filehash.path): filehash for filehash in hashed_files2}
        checksum_summary = summarize_checksums(
            rootfs_path1, hashed_files1, rootfs_path2, hashed_files2
        )
        diff_lookup = build_diff_lookup(diff_list)
        trivial_diffs, nontrivial_diffs = classify_checksum_mismatches(
            checksum_summary, diff_lookup, files1, files2
        )
        files_summary.append(
            {
                "image1": checksum_summary["image1"],
                "image2": checksum_summary["image2"],
                "only_in_image1": checksum_summary["only_in_image1"],
                "only_in_image2": checksum_summary["only_in_image2"],
                "trivial_checksum_different_files": trivial_diffs,
                "nontrivial_checksum_different_files": nontrivial_diffs,
            }
        )
        if file_checksum:
            files_summary.append(
                {
                    "checksum_mismatches": checksum_summary[
                        "checksum_mismatches"
                    ],
                    "checksum_matches": checksum_summary["checksum_matches"],
                }
            )

        return (
            unknown_issues_count,
            trivial_issues_count,
            nontrivial_issues_count,
            diff_list,
            files_summary,
            checksum_summary,
        )

    return (
        unknown_issues_count,
        trivial_issues_count,
        nontrivial_issues_count,
        diff_list,
        files_summary,
        checksum_summary,
    )
