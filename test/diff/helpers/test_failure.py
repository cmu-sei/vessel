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

"""Tests for Failure class."""

# -----------------------------------------------------------------------------
# Tests for make_failure_dict
# -----------------------------------------------------------------------------

import pytest
from test.fixture import get_test_flag
from vessel.diff.helpers.diffline import DiffLine
from vessel.diff.helpers.failure import Failure


TEST_ISSUE_DICT_INPUT = [
    (
        {},
        {
            "minus_file_line_number": None,
            "plus_file_line_number": None,
            "minus_diff_line_number": None,
            "plus_diff_line_number": None,
            "minus_unmatched_str": None,
            "plus_unmatched_str": None,
        },
    ),
    (
        {
            "minus_line": DiffLine("example 123", 1, 2),
            "plus_line": DiffLine("example 456", 3, 4),
            "minus_str": "123",
            "plus_str": "456",
            "flag": None,
        },
        {
            "minus_file_line_number": 2,
            "plus_file_line_number": 4,
            "minus_diff_line_number": 1,
            "plus_diff_line_number": 3,
            "minus_unmatched_str": "123",
            "plus_unmatched_str": "456",
        },
    ),
    (
        {
            "minus_line": DiffLine("example 123", 1, 2),
            "plus_line": DiffLine("example 456", 3, 4),
            "minus_str": "123",
            "plus_str": "456",
            "flag": get_test_flag(),
        },
        {
            "id": "test_flag",
            "description": "test flag",
            "minus_file_line_number": 2,
            "plus_file_line_number": 4,
            "minus_diff_line_number": 1,
            "plus_diff_line_number": 3,
            "minus_matched_str": "123",
            "plus_matched_str": "456",
        },
    ),
]


@pytest.mark.parametrize("test_input, expected", TEST_ISSUE_DICT_INPUT)
def test_failure_to_dict(test_input, expected):
    """Tests that the failure.to_dict() is created properly."""

    dict = Failure(**test_input).to_dict()

    assert dict == expected