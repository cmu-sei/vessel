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

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any, Optional

from vessel.diff.helpers.diffline import DiffLine
from vessel.diff.helpers.flag import Flag


@dataclass
class FailureSummary:
    """Represents a summary of failures in OCI image."""

    # TODO: Make these unknown_failure_count, then adjust the to_dict to output as it is now

    unknown_failures: int = 0
    """Number of failures that did not match a flag."""

    flagged_failures: int = 0
    """Number of failures that did match a flag."""

    trivial_failures: int = 0
    """Number of failures that matched a flag with a severity of as Low."""

    nontrivial_failures: int = 0
    """Number of failures that matched a flag with a severity different than Low."""

    total_failures: int = 0
    """Total number of failures found."""

    def to_dict(self) -> dict[str, Any]:
        """Returns this as a dictionary."""
        return asdict(self)

    def __init__(
        self,
        unknown_failure_count: int = 0,
        trivial_failure_count: int = 0,
        nontrivial_failure_count: int = 0,
    ):
        """Constructor, gets 3 independent values (unknown, trivial, nontrivial), aggregates the rest."""
        self.unknown_failures = unknown_failure_count
        self.trivial_failures = trivial_failure_count
        self.nontrivial_failures = nontrivial_failure_count

        # Calculate the aggregated values as well.
        self.calculate_aggregated_values()

    def calculate_aggregated_values(self) -> None:
        """Calculates and sets the aggregated values from the three basic ones."""
        self.flagged_failures = (
            self.trivial_failures + self.nontrivial_failures
        )
        self.total_failures = (
            self.unknown_failures
            + self.trivial_failures
            + self.nontrivial_failures
        )


class Failure:
    """Represents a reproduciblity failure."""

    def __init__(
        self: "Failure",
        minus_line: Optional[DiffLine] = None,
        plus_line: Optional[DiffLine] = None,
        minus_str: Optional[str] = None,
        plus_str: Optional[str] = None,
        flag: Optional[Flag] = None,
        comments: Optional[list[str]] = None,
    ) -> None:
        """
        
            TODO: Comments are used only for binary, can they be passed to the parent? seems hard
        """
        self.minus_line = minus_line
        self.plus_line = plus_line
        self.minus_str = minus_str
        self.plus_str = plus_str
        self.flag = flag
        self.comments = comments

    def to_dict(self) -> dict[str, Any]:
        """Returns this failure as a dictionary.
        
        A flag being passed implies that it was a flagged failure and the flag information
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
        # Handle binary elements that have comments in the Failure
        if self.comments:
            if self.flag:
                return {
                    "id": self.flag.flag_id,
                    "description": self.flag.description,
                    "metadata": self.flag.metadata,
                    "severity": self.flag.severity,
                    "comments": self.comments
                }
            else:
                return {
                    "comments": self.comments
                }

        # Handle nonbinary flagged
        elif self.flag:
            return {
                "id": self.flag.flag_id,
                "description": self.flag.description,
                "minus_file_line_number": self.minus_line.file_line_number
                if self.minus_line
                else None,
                "plus_file_line_number": self.plus_line.file_line_number
                if self.plus_line
                else None,
                "minus_diff_line_number": self.minus_line.diff_line_number
                if self.minus_line
                else None,
                "plus_diff_line_number": self.plus_line.diff_line_number
                if self.plus_line
                else None,
                "minus_matched_str": self.minus_str,
                "plus_matched_str": self.plus_str,
                "metadata": self.flag.metadata,
                "severity": self.flag.severity,
            }
        
        # Handle nonbinary unknown
        return {
            "minus_file_line_number": self.minus_line.file_line_number
            if self.minus_line
            else None,
            "plus_file_line_number": self.plus_line.file_line_number
            if self.plus_line
            else None,
            "minus_diff_line_number": self.minus_line.diff_line_number
            if self.minus_line
            else None,
            "plus_diff_line_number": self.plus_line.diff_line_number
            if self.plus_line
            else None,
            "minus_unmatched_str": self.minus_str,
            "plus_unmatched_str": self.plus_str,
        }
