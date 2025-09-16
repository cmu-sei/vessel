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

"""Utility class for flag operations"""
# TODO rename this file

from pathlib import Path
import re
import magic
from vessel.diff.helpers.diffline import DiffLine
from vessel.diff.helpers.failure import Failure, FailureSummary
from vessel.diff.helpers.file_diff import FileDiff
from vessel.diff.helpers.flag import Flag
from vessel.utils.unified_diff import failures_from_difflines

# TODO Better naming for this and all functions
def check_flags(
    flags: list[Flag],
    filetype_lookup1,
    filetype_lookup2,
    file_diff: FileDiff,
    minus_line: DiffLine,
    plus_line: DiffLine,
    is_binary: bool,
) -> tuple[FailureSummary, list, list]: # TODO List typing
    """Check a FileDiff against all Flags and return summary, and list of flagged and unknown failures.

    Take in a FileDiff, iterate through all of the Flags and check if each matches the difference and
    the minus and plus lines of the FileDiff while updating the failure counts, and the lists of
    failures in the FileDiff parameter object.

    Args:
        flags: List of Flags to be checked against
        file_diff: FileDiff object to be checked
        filetype_lookup1: TODO
        filetype_lookpu2: TODO
        minus_line: Line of the minus file in the unified diff to be checked
        plus_line: Line of the plus file in the unified diff to be checked
        is_binary: Boolean to determine if the FileDiff is from a binary file or not
    
    Returns:
        Failure
    """
    failure_summary = FailureSummary()
    flagged_failure_list = [] # list[Failure] TODO
    unknown_failure_list = [] # list[Failure] TODO

    for flag in flags:
        flag_matches = True

        # Check if filepath matches flag
        flag_matches = _check_flag_filepath(
            flag, file_diff.source1, file_diff.source2
        )

        # Check if filetype matches flag
        if flag_matches:
            flag_matches = _check_flag_filetype(
                flag, filetype_lookup1, filetype_lookup2, file_diff.source1, file_diff.source2
            )

        # Check if command matches flag
        if flag_matches:
            flag_matches = _check_flag_command(flag, file_diff.command)

        # Check if comment matches flag
        if flag_matches:
            flag_matches = _check_flag_comment(flag, file_diff.comments)

        # Handle a binary line that matches the flag
        if (
            flag_matches
            and is_binary
            and flag.regex["indiff"] == re.compile(".*")
        ):
            flagged_failure_list.append(
                Failure(
                    flag=flag,
                    comments=[
                        "Flag indiff regex are not ran on binary "
                        "unified diff. However this matched all "
                        "of the other criteria for this flag.",
                    ]
                )
            )
        # Handle any non-binary line that matches the flag
        elif flag_matches:
            (
                temp_flagged_failure_list,
                temp_unknown_failure_list,
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
                failure.flag.flag_id for failure in file_diff.flagged_failures
            ]:
                for failure in temp_flagged_failure_list:
                    if flag.severity == "Low":
                        failure_summary.trivial_failures += 1
                    else:
                        failure_summary.nontrivial_failures += 1
                failure_summary.unknown_failures += len(temp_unknown_failure_list)
                flagged_failure_list.extend(temp_flagged_failure_list)
                unknown_failure_list.extend(temp_unknown_failure_list)
    
    return failure_summary, flagged_failure_list, unknown_failure_list

def _check_flag_filepath(
    flag: Flag, source1: str, source2: str
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
    flag: Flag, filetype_lookup1, filetype_lookup2, source1: str, source2: str
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
            filetype_lookup1 is not None
            and filetype_lookup2 is not None
        ):
            file_type_1 = filetype_lookup1.get(source1, "")
            file_type_2 = filetype_lookup2.get(source2, "")

            if file_type_1 and file_type_2:
                if not flag.regex["filetype"].search(
                    file_type_1
                ) or not flag.regex["filetype"].search(file_type_2):
                    return False

    return True

def _check_flag_command(
    flag: Flag, command: str
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
    flag: Flag, comments: list
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
