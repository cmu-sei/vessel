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

"""Utility Unified Diff functions."""

import re
import typing
from logging import getLogger
from typing import Any, Optional

import portion  # type: ignore

from vessel.utils.flag import Flag

logger = getLogger(__name__)


class Diff:
    """Class to hold all the data used when parsing a unified diff."""

    def __init__(
        self: "Diff",
        source1: str,
        source2: str,
        parent_source1: str,
        parent_source2: str,
        comments: list,
        raw_unified_diff: str,
    ) -> None:
        """Initializer for Diff class."""
        self.source1 = source1
        self.source2 = source2
        self.parent_source1 = parent_source1
        self.parent_source2 = parent_source2
        self.unified_diff: list[str] = raw_unified_diff.splitlines()
        self.comments: list[str] = comments
        self.command: str = ""

        self.flagged_failures: list[dict] = []
        self.unknown_failures: list[dict] = []

        self.minus_aligned_lines: list[DiffLine] = []
        self.plus_aligned_lines: list[DiffLine] = []
        self.minus_aligned_lines, self.plus_aligned_lines = align_diff_lines(
            self.unified_diff,
        )

    def to_slim_dict(self: "Diff") -> dict:
        """Returns diff object as a dict.

        Returns a dict object only containing parts of the diff that are
        populated. This is done to reduce the size of the output file.
        """
        dict_obj: dict[str, Any] = {
            "source1": self.source1,
            "source2": self.source2,
        }
        dict_obj["unified_diff_id"] = "ID not yet assigned"
        if self.command:
            dict_obj["command"] = self.command
        if self.comments:
            dict_obj["comments"] = self.comments
        dict_obj["unified_diff"] = self.unified_diff
        if self.flagged_failures:
            dict_obj["flagged_failures"] = self.flagged_failures
        if self.unknown_failures:
            dict_obj["unknown_failures"] = self.unknown_failures

        return dict_obj


class DiffLine:
    """Class to hold data while processing a line in a unified diff."""

    def __init__(
        self: "DiffLine",
        text: str,
        diff_line_number: Optional[int] = None,
        file_line_number: Optional[int] = None,
    ) -> None:
        """Initializer for DiffLine class."""
        self.text = text
        self.diff_line_number = diff_line_number
        self.file_line_number = file_line_number
        # Interval object containing the range of self.text that
        #   have not been matched by any of the flag['indiff'] regex
        self.unmatched_intervals = portion.closed(0, len(self.text) - 1)

    def __eq__(self, other: object):
        if isinstance(other, DiffLine):
            return (
                self.text == other.text
                and self.diff_line_number == other.diff_line_number
                and self.file_line_number == self.file_line_number
                and self.unmatched_intervals == other.unmatched_intervals
            )
        return False


def equal_entry_list(
    list1: list[Any],
    list2: list[Any],
    fill_value: Optional[Any] = None,
) -> tuple[list, list]:
    """Return two lists of even length with from two lists.

    Accepts two lists, appends fillvalue to the shorter of the two to make the
    lengths even.

    Args:
        list1: First list to potentially append to
        list2: Second list to potentially append to
        fillvalue: Value appended to each list until they are even length

    Returns:
        Two lists of the same length
    """
    # TODO : Match these up better. Quite a few potential failures with different
    #           number of lines diffs and such may not be fixable here though
    #           and would just have to be a better diff tool in diffoscope to
    #           give better unified diffs. Very hard to line up lines without
    #           context
    while len(list1) < len(list2):
        list1.append(fill_value)
    while len(list2) < len(list1):
        list2.append(fill_value)

    return list1, list2


def parse_unified_diff_header(header_line: str) -> tuple[int, int]:
    """Return starting line of diff in each file from unified diff header.

    Args:
        header_line: String containing the first line of a unified diff

    Returns:
        Starting line of the diff in the first file and starting line of the
            diff in the second file
    """
    header_stripped = header_line.strip("@- ")
    header_split = header_stripped.split(" +")
    minus = header_split[0].split(",")
    plus = header_split[1].split(",")

    return int(minus[0]), int(plus[0])


def align_diff_lines(
    unified_diff: list,
) -> tuple[list[DiffLine], list[DiffLine]]:
    """Pairs lines with diffs from a unified diff.

    Reads in a unified diff, pairs all of the - lines with + lines in the same
    block. Uneven number of - and + lines will be made even with empty strings
    and then the next block will be processed. Each item in the returned lists
    is a DiffLine item containing the line, and its line number in the diff,
    and its line number in the file. Any uneven number of lines is filled in
    with an empty DiffLine so the lists returned will always be of even length.

    Args:
        unified_diff: A unified diff as a list with each line being a string
                        element in the list

    Returns:
        Two lists of even length containing the lines with differences from
        their respective files, the line number in the diff, and the line
        number in the file.
    """
    minus_aligned_lines = []
    plus_aligned_lines = []
    minus_file_line_index, plus_file_line_index = parse_unified_diff_header(
        unified_diff[0],
    )

    unified_diff_header_regex = re.compile(
        r"\@\@ -\d+(,\d+)? \+\d+(,\d+)? \@\@"
    )

    index = 1
    while index < len(unified_diff):
        if unified_diff_header_regex.search(unified_diff[index]):
            minus_file_line_index, plus_file_line_index = (
                parse_unified_diff_header(unified_diff[index])
            )
            index += 1
        elif unified_diff[index][0] == "-" or unified_diff[index][0] == "+":
            while index < len(unified_diff) and (
                unified_diff[index][0] == "-" or unified_diff[index][0] == "+"
            ):
                if unified_diff[index][0] == "-":
                    minus_aligned_lines.append(
                        DiffLine(
                            unified_diff[index][1:],
                            index,
                            minus_file_line_index,
                        ),
                    )
                    minus_file_line_index += 1
                    index += 1
                else:
                    plus_aligned_lines.append(
                        DiffLine(
                            unified_diff[index][1:],
                            index,
                            plus_file_line_index,
                        ),
                    )
                    plus_file_line_index += 1
                    index += 1

            minus_aligned_lines, plus_aligned_lines = equal_entry_list(
                minus_aligned_lines,
                plus_aligned_lines,
                DiffLine(""),
            )
        else:
            minus_file_line_index += 1
            plus_file_line_index += 1
            index += 1

    return minus_aligned_lines, plus_aligned_lines


def failures_from_difflines(
    minus_line: DiffLine,
    plus_line: DiffLine,
    flag: Flag,
) -> tuple[list, list, portion.interval.Interval, portion.interval.Interval]:
    """Checks lines against flag indiff regex and returns matched intervals.

    Input is two lines and their unmatched intervals. Checks each line for
    matches with flag and then returns any flagged or unknown failures along
    with updated unmatched intervals.

    If portions of a line are unmatched by regex, but are the same as the
    portion of the relative - or + line it will not be shown as an failure.

    Args:
        minus_line: DiffLine object containing the minus line
        plus_line: DiffLine object containing the plus line
        flag: dict object containing regex to match against diff objects.
                Entry from `config/diff_config.yaml`

    :return: List of flagged failures, list of unknown failures, updated intervals
                in each line that haven't been matched by regex
    """
    flagged_failures: list[dict[str, Any]] = []
    unknown_failures: list[dict[str, Any]] = []
    minus_matched_intervals = (
        [
            match.span()
            for match in flag.regex["indiff"].finditer(minus_line.text)
        ]
        if minus_line
        else []
    )
    plus_matched_intervals = (
        [
            match.span()
            for match in flag.regex["indiff"].finditer(plus_line.text)
        ]
        if plus_line
        else []
    )
    minus_matched_intervals, plus_matched_intervals = equal_entry_list(
        minus_matched_intervals,
        plus_matched_intervals,
        None,
    )

    for minus_match_interval, plus_match_interval in zip(
        minus_matched_intervals,
        plus_matched_intervals,
        strict=False,
    ):
        minus_match_str = ""
        if minus_match_interval is not None:
            minus_line.unmatched_intervals = (
                minus_line.unmatched_intervals
                - portion.closed(
                    minus_match_interval[0],
                    minus_match_interval[1] - 1,
                )
            )
            minus_match_str = intervals_to_str(
                minus_line.text,
                portion.closed(
                    minus_match_interval[0],
                    minus_match_interval[1] - 1,
                ),
            )

        plus_match_str = ""
        if plus_match_interval is not None:
            plus_line.unmatched_intervals = (
                plus_line.unmatched_intervals
                - portion.closed(
                    plus_match_interval[0],
                    plus_match_interval[1] - 1,
                )
            )
            plus_match_str = intervals_to_str(
                plus_line.text,
                portion.closed(
                    plus_match_interval[0], plus_match_interval[1] - 1
                ),
            )

        if minus_match_interval is None:
            unknown_failures.append(
                make_failure_dict(
                    minus_line,
                    plus_line,
                    None,
                    plus_match_str,
                ),
            )
        elif plus_match_interval is None:
            unknown_failures.append(
                make_failure_dict(
                    minus_line,
                    plus_line,
                    minus_match_str,
                    None,
                ),
            )
        elif minus_match_str != plus_match_str:
            flagged_failures.append(
                make_failure_dict(
                    minus_line,
                    plus_line,
                    minus_match_str,
                    plus_match_str,
                    flag,
                ),
            )

    return (
        flagged_failures,
        unknown_failures,
        minus_line.unmatched_intervals,
        plus_line.unmatched_intervals,
    )


def make_failure_dict(
    minus_line: Optional[DiffLine] = None,
    plus_line: Optional[DiffLine] = None,
    minus_str: Optional[str] = None,
    plus_str: Optional[str] = None,
    flag: Optional[Flag] = None,
) -> dict[str, Any]:
    """Create failure dict object.

    Used to ensure consistency in all failure objects that
    will be written to final output file. A flag being passed
    implies that it was a flagged failure and the flag information
    will be embedded in the dict.

    Args:
        minus_line: Diff line object containing the minus line
        plus_line: Diff line object containing the plus line
        minus_str: String that was matched or unmatched in the minus line
        plus_str: String that was matched or unmatched in the plus line
        flag: Dict item of the flag to have id and description

    Returns:
        A failure dict item.
    """
    if flag:
        return {
            "id": flag.flag_id,
            "description": flag.description,
            "minus_file_line_number": minus_line.file_line_number
            if minus_line
            else None,
            "plus_file_line_number": plus_line.file_line_number
            if plus_line
            else None,
            "minus_diff_line_number": minus_line.diff_line_number
            if minus_line
            else None,
            "plus_diff_line_number": plus_line.diff_line_number
            if plus_line
            else None,
            "minus_matched_str": minus_str,
            "plus_matched_str": plus_str,
        }

    return {
        "minus_file_line_number": minus_line.file_line_number
        if minus_line
        else None,
        "plus_file_line_number": plus_line.file_line_number
        if plus_line
        else None,
        "minus_diff_line_number": minus_line.diff_line_number
        if minus_line
        else None,
        "plus_diff_line_number": plus_line.diff_line_number
        if plus_line
        else None,
        "minus_unmatched_str": minus_str,
        "plus_unmatched_str": plus_str,
    }


def intervals_to_str(
    input_string: str,
    intervals: portion.interval.Interval,
) -> str:
    """Returns characters in a string contained in specified intervals.

    Returns string containing the characters in the input string
    that are in the ranges specifiec by the interval parameter.
    Appriately handles open and closed ends of the intervals used
    by the Portion library. Does not handle singleton.

    Args:
        input_string: String to take sections out of
        intervals: Interval object defining which intervals to select

    Returns:
      string containing the intervals of the input string specified in the
      intervals object
    """
    output_str = ""
    for interval in intervals:
        lower = (
            # interval.lower is of type int
            typing.cast(int, interval.lower) + 1
            if interval.left == portion.OPEN
            else interval.lower
        )
        upper = (
            # interval.upper is of type int
            typing.cast(int, interval.upper) + 1
            if interval.right == portion.CLOSED
            else interval.upper
        )
        output_str = output_str + input_string[lower:upper]

    return output_str
