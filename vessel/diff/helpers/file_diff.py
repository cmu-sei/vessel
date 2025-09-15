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

"""@@@@@"""

from typing import Any

from vessel.diff.helpers.diffline import DiffLine
from vessel.utils.unified_diff import align_diff_lines


class FileDiff:
    """An entry describing a diff between two files."""

    def __init__(
        self: "FileDiff",
        source1: str,
        source2: str,
        comments: list,
        raw_unified_diff: str,
    ) -> None:
        """Initializer for Diff class."""
        self.source1 = source1
        self.source2 = source2
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

    def to_dict(self: "FileDiff") -> dict[str, Any]:
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
            dict_obj["flagged_failures"] = [failure for failure in self.flagged_failures]
        if self.unknown_failures:
            dict_obj["unknown_failures"] = [failure for failure in self.unknown_failures]

        return dict_obj
    

class FileDiffs:
    """Encapsulates a list of file diffs."""

    def __init__(self, diffs: list[FileDiff] = []):
        """Constructor."""
        self.diffs = diffs
        """List of diffs in files."""

    def to_dict_list(self) -> list[dict[str, Any]]:
        """Returns this diff as a list of dictionaries."""
        return [diff.to_dict() for diff in self.diffs]