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


from typing import Any

from vessel.diff.helpers.failure import Failure
from vessel.diff.helpers.unified_diff import align_diff_lines


class FileDiff:
    """Class describing a diff between two files."""

    def __init__(
        self: "FileDiff",
        source1: str,
        source2: str,
        comments: list[str],
        raw_unified_diff: str,
    ) -> None:
        """Initializer for Diff class."""
        self.source1 = source1
        self.source2 = source2
        self.comments: list[str] = comments
        self.unified_diff: list[str] = raw_unified_diff.splitlines()

        self.unified_diff_id = -1
        self.command: str = ""
        self.flagged_failures: list[Failure] = []
        self.unknown_failures: list[Failure] = []

        self.minus_aligned_lines, self.plus_aligned_lines = align_diff_lines(
            self.unified_diff,
        )

    def __eq__(self, other: object):
        if isinstance(other, FileDiff):
            return (
                self.source1 == other.source1
                and self.source2 == other.source2
                and self.comments == other.comments
                and self.unified_diff == other.unified_diff
                and self.unified_diff_id == other.unified_diff_id
                and self.command == other.command
                and self.flagged_failures == other.flagged_failures
                and self.unknown_failures == other.unknown_failures
            )
        return False

    def to_dict(self: "FileDiff") -> dict[str, Any]:
        """Returns diff object as a dict.

        Returns a dict object only containing parts of the diff that are
        populated. This is done to reduce the size of the output file.
        """
        dict_obj: dict[str, Any] = {
            "source1": self.source1,
            "source2": self.source2,
        }
        dict_obj["unified_diff_id"] = self.unified_diff_id
        if self.command:
            dict_obj["command"] = self.command
        if self.comments:
            dict_obj["comments"] = self.comments
        if self.flagged_failures:
            dict_obj["flagged_failures"] = [
                failure.to_dict() for failure in self.flagged_failures
            ]
        if self.unknown_failures:
            dict_obj["unknown_failures"] = [
                failure.to_dict() for failure in self.unknown_failures
            ]

        return dict_obj


class FileDiffs:
    """Encapsulates a list of file diffs."""

    def __init__(self, diffs: list[FileDiff] | None = None):
        """Constructor."""
        if diffs:
            self.diffs = diffs
        else:
            self.diffs = []
        """List of diffs in files."""

    def __eq__(self, other: object):
        if isinstance(other, FileDiffs):
            return self.diffs == other.diffs
        return False

    def to_dict_list(self) -> list[dict[str, Any]]:
        """Returns this diff as a list of dictionaries."""
        return [diff.to_dict() for diff in self.diffs]
