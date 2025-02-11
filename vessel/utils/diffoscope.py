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

import magic

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
    cmd.extend(["--json", output_dir_path + "/" + output_file_name])

    if compare_level == "file":
        cmd.append("--new-file")

    cmd.extend([path1, path2])
    return cmd


def parse_diffoscope_output(
    current_detail: dict,
    flags: list[Flag],
    parent_source1: str = "",
    parent_source2: str = "",
    parent_comments: list[str] | None = None,
) -> tuple[int, int, list]:
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

    Returns:
        Count of unknown issues, count of flagged issues and diff list
        containing specifics about each issue
    """
    flagged_issues_count = 0
    unknown_issues_count = 0
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
                    current_detail["source1"],
                ) or not flag.regex["filepath"].search(
                    current_detail["source2"],
                ):
                    flag_matches = False

                # Check if filetype matches flag
                if (
                    flag_matches
                    and Path(current_detail["source1"]).is_file()
                    and Path(current_detail["source2"]).is_file()
                ):
                    file_type_1 = magic.from_file(
                        current_detail["source1"],
                    )
                    file_type_2 = magic.from_file(
                        current_detail["source2"],
                    )

                    if not flag.regex["filetype"].search(
                        file_type_1,
                    ) or not flag.regex["filetype"].search(file_type_2):
                        flag_matches = False

                # Check if command matches flag
                if flag_matches and (
                    (
                        diff.command != ""
                        and not flag.regex["command"].search(diff.command)
                    )
                    or (
                        diff.command == ""
                        and flag.regex["command"] != re.compile(".")
                    )
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
                        and flag.regex["comment"] != re.compile(".")
                    )
                ):  # fmt: skip
                    flag_matches = False

                # Handle a binary line that matches the flag
                if (
                    flag_matches
                    and is_binary
                    and flag.regex["indiff"] == re.compile(".")
                ):
                    flagged_issues_count += 1
                    diff.flagged_issues.append(
                        {
                            "id": flag.flag_id,
                            "description": flag.description,
                            "comments": [
                                "Flag indiff regex are not ran on binary "
                                "unified diff. However this matched all "
                                "of the other criteria for this flag. and "
                                "indiff was set to '.'",
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
                    flagged_issues_count += len(flagged_issue_list)
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

        diff_list.append(diff.to_dict())

    # Recurvisely navigating through the tree
    if "details" in current_detail:
        for child in current_detail["details"]:
            child_return = parse_diffoscope_output(
                child,
                flags,
                current_detail["source1"],
                current_detail["source2"],
                current_detail.get("comments"),
            )
            unknown_issues_count += child_return[0]
            flagged_issues_count += child_return[1]
            diff_list.extend(child_return[2])

    return unknown_issues_count, flagged_issues_count, diff_list
