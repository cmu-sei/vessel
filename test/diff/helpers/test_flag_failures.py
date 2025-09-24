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

"""Tests for flag failures"""

from vessel.diff.helpers import flag_failures
from vessel.diff.helpers.diffline import DiffLine
from vessel.diff.helpers.failure import Failure, FailureSummary
from vessel.diff.helpers.file_diff import FileDiff
from vessel.diff.helpers.flag import Flag


def generate_flag(
    filepath=".*",
    filetype=".*",
    command=".*",
    comment=".*",
    indiff=".*",
    severity="Low",
):
    return Flag(
        flag_id="TEST",
        description="hello",
        severity=severity,
        metadata=False,
        filepath=filepath,
        filetype=filetype,
        command=command,
        comment=comment,
        indiff=indiff,
    )


def generate_file_diff():
    """Make a minimal FileDiff for testing"""
    return FileDiff(
        "src1.txt",
        "src2.txt",
        ["Similarity: 0.90625%"],
        "@@ -1,1 +1,1 @@\n-old\n+new\n",
    )


def test_check_flag_filepath_patches_and_fails():
    flag = generate_flag(filepath="src")
    assert flag_failures._check_flag_filepath(flag, "src.txt", "src2.txt")

    mismatch_flag = generate_flag(filepath="abc")
    assert not flag_failures._check_flag_filepath(
        mismatch_flag, "src1.txt", "src2.txt"
    )


def test_check_flag_command_matches_and_fails():
    flag = generate_flag(command="stat")
    assert flag_failures._check_flag_command(flag, "stat {}")
    assert not flag_failures._check_flag_command(flag, "other")


def test_check_flag_comment_matches_and_fails():
    flag = generate_flag(comment="Similarity: 0.90625%")
    assert flag_failures._check_flag_comment(flag, ["Similarity: 0.90625%"])
    flag = generate_flag(comment="different")
    assert not flag_failures._check_flag_comment(
        flag, ["Similarity: 0.90625%"]
    )
    flag = generate_flag(comment="abc")
    assert not flag_failures._check_flag_comment(flag, [])


def test_check_flag_filetype_with_metadata_lookup():
    flag = generate_flag(filetype="text")

    file1 = "src1.txt"
    file2 = "src2.txt"
    lookup1 = {file1: "text/plain"}
    lookup2 = {file2: "text/plain"}
    assert flag_failures._check_flag_filetype(
        flag, lookup1, lookup2, file1, file2
    )

    lookup1 = {file1: "application/binary"}
    lookup2 = {file2: "application/binary"}
    assert not flag_failures._check_flag_filetype(
        flag, lookup1, lookup2, file1, file2
    )


def test_flag_failures_binary_match():
    file_diff = generate_file_diff()
    minus = DiffLine("-old", 1, 1)
    plus = DiffLine("+new", 2, 2)

    flag = generate_flag(indiff=".*", severity="Low")
    summary, flagged, unknown = flag_failures.flag_failures(
        [flag], file_diff, None, None, minus, plus, is_binary=True
    )

    assert isinstance(summary, FailureSummary)
    assert len(flagged) == 1
    assert len(unknown) == 0
    assert flagged[0].binary is True
    assert summary.trivial_failure_count == 0
    assert summary.nontrivial_failure_count == 0
    assert summary.unknown_failure_count == 0



def test_flag_failures_nonbinary_match_counts(monkeypatch):
    file_diff = generate_file_diff()
    minus = DiffLine("-old", 1, 1)
    plus = DiffLine("+new", 2, 2)

    def simulate_failures_from_difflines(*args, **kwargs):
        return (
            [Failure(flag=generate_flag(severity="Low"))],
            [Failure()],
            minus.unmatched_intervals,
            plus.unmatched_intervals,
        )

    monkeypatch.setattr(
        flag_failures,
        "failures_from_difflines",
        simulate_failures_from_difflines,
    )

    flag = generate_flag(indiff="old")
    summary, flagged, unknown = flag_failures.flag_failures(
        [flag], file_diff, None, None, minus, plus, is_binary=False
    )

    assert isinstance(summary, FailureSummary)
    assert len(flagged) == 1
    assert len(unknown) == 1
    assert flagged[0].binary is None
    assert summary.trivial_failure_count == 1
    assert summary.unknown_failure_count == 1
