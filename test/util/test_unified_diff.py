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
"""Tests for Unified Diff functions."""

import portion
import pytest

from test.fixture import get_test_flag
from vessel.utils.unified_diff import (
    Diff,
    DiffLine,
    align_diff_lines,
    equal_entry_list,
    failures_from_difflines,
    intervals_to_str,
    make_failure_dict,
    parse_unified_diff_header,
)

# -----------------------------------------------------------------------------
# Tests for Diff.to_slim_dict
# -----------------------------------------------------------------------------

TEST_DIFF_CLASS_OBJECTS = [
    (
        Diff(
            "src1",
            "src2",
            "par src1",
            "par src2",
            ["com1", "com2"],
            "@@ -1,2 +1,3 @@\n 1\n-2\n+2!\n+3!\n",
        ),
        {
            "source1": "src1",
            "source2": "src2",
            "unified_diff_id": "ID not yet assigned",
            "comments": ["com1", "com2"],
            "unified_diff": "@@ -1,2 +1,3 @@\n 1\n-2\n+2!\n+3!\n".splitlines(),
        },
    )
]


@pytest.mark.parametrize("test_input, expected", TEST_DIFF_CLASS_OBJECTS)
def test_Diff_to_sim_dict(test_input, expected):
    """Ensures Diff properly converts to a dict"""

    dict = test_input.to_slim_dict()

    assert dict == expected


# -----------------------------------------------------------------------------
# Tests for DiffLine
# -----------------------------------------------------------------------------

TEST_DIFFLINE_DATA = [
    (
        {"text": "012345", "diff_line_number": 7, "file_line_number": 8},
        {"text": "012345", "diff_line_number": 7, "file_line_number": 8},
    )
]


@pytest.mark.parametrize("test_input, expected", TEST_DIFFLINE_DATA)
def test_DiffLine(test_input, expected):
    """Tests for DiffLine class."""

    diffline = DiffLine(**test_input)

    assert diffline.diff_line_number == expected["diff_line_number"]
    assert diffline.file_line_number == expected["file_line_number"]
    assert (
        intervals_to_str(diffline.text, diffline.unmatched_intervals)
        == expected["text"]
    )


# -----------------------------------------------------------------------------
# Tests for equal_entry_list
# -----------------------------------------------------------------------------

TEST_LISTS = [
    (
        {"list1": [1, 2], "list2": [1, 2, 3], "fill_value": -1},
        {"list1": [1, 2, -1], "list2": [1, 2, 3]},
    ),
    (
        {"list1": [1, 2], "list2": [1, 2, 3, 4, 5], "fill_value": -1},
        {"list1": [1, 2, -1, -1, -1], "list2": [1, 2, 3, 4, 5]},
    ),
    (
        {"list1": [1, 2, 3], "list2": [1, 2], "fill_value": -1},
        {"list1": [1, 2, 3], "list2": [1, 2, -1]},
    ),
    (
        {"list1": [1, 2, 3, 4, 5], "list2": [1, 2], "fill_value": -1},
        {"list1": [1, 2, 3, 4, 5], "list2": [1, 2, -1, -1, -1]},
    ),
    ({"list1": [], "list2": [], "fill_value": -1}, {"list1": [], "list2": []}),
    (
        {"list1": [], "list2": [1], "fill_value": -1},
        {"list1": [-1], "list2": [1]},
    ),
    (
        {"list1": [], "list2": [1, 2], "fill_value": -1},
        {"list1": [-1, -1], "list2": [1, 2]},
    ),
    (
        {"list1": [1], "list2": [], "fill_value": -1},
        {"list1": [1], "list2": [-1]},
    ),
    (
        {"list1": [1, 2], "list2": [], "fill_value": -1},
        {"list1": [1, 2], "list2": [-1, -1]},
    ),
]


@pytest.mark.parametrize("test_input, expected", TEST_LISTS)
def test_equal_entry_list(test_input: dict, expected: dict):
    """Tests that inputted lists are returned equal length with the correct fill value."""

    equal_list1, equal_list2 = equal_entry_list(**test_input)

    assert equal_list1 == expected["list1"]
    assert equal_list2 == expected["list2"]


# -----------------------------------------------------------------------------
# Tests for parse_unified_diff_header
# -----------------------------------------------------------------------------

TEST_UNIFIED_DIFF_HEADERS = [
    ("@@ -8,13 +15,13 @@", (8, 15)),
    ("@@ -0,0 +1 @@", (0, 1)),
    ("@@ -1 +0,0 @@", (1, 0)),
]


@pytest.mark.parametrize("test_input, expected", TEST_UNIFIED_DIFF_HEADERS)
def test_parse_unified_diff_header(test_input: str, expected: tuple[int, int]):
    """Tests that the unified diff header is parsed correctly to return start lines of the diffs."""

    line_num1, line_num2 = parse_unified_diff_header(test_input)

    assert (line_num1, line_num2) == expected


# -----------------------------------------------------------------------------
# Tests for align_diff_lines
# -----------------------------------------------------------------------------

TEST_UNIFIED_DIFFS = [
    # 1 block. 1 minus line, 2 plus line
    (
        "@@ -1,2 +1,3 @@\n 1\n-2\n+2!\n+3!\n",
        {
            "list1": [DiffLine("2", 2, 2), DiffLine("")],
            "list2": [DiffLine("2!", 3, 2), DiffLine("3!", 4, 3)],
        },
    ),
    # 1 block. 1 minus line, 4 plus line
    (
        "@@ -1,2 +1,5 @@\n 1\n-2\n+2!\n+3!\n+4!\n+5!\n",
        {
            "list1": [
                DiffLine("2", 2, 2),
                DiffLine(""),
                DiffLine(""),
                DiffLine(""),
            ],
            "list2": [
                DiffLine("2!", 3, 2),
                DiffLine("3!", 4, 3),
                DiffLine("4!", 5, 4),
                DiffLine("5!", 6, 5),
            ],
        },
    ),
    # 2 blocks. Block 1: 1 minus line, 2 plus line. Block 2: 1 minus line, 2 plus line.
    (
        "@@ -1,4 +1,6 @@\n 1\n-2\n+2!\n+3!\n \n-4\n+4!\n+5!\n",
        {
            "list1": [
                DiffLine("2", 2, 2),
                DiffLine(""),
                DiffLine("4", 6, 4),
                DiffLine(""),
            ],
            "list2": [
                DiffLine("2!", 3, 2),
                DiffLine("3!", 4, 3),
                DiffLine("4!", 7, 5),
                DiffLine("5!", 8, 6),
            ],
        },
    ),
    # 2 blocks. Block 1: 1 minus line, 4 plus line. Block 2: 1 minus line, 4 plus line.
    (
        "@@ -1,4 +1,10 @@\n 1\n-2\n+2!\n+3!\n+4!\n+5!\n \n-6\n+6!\n+7!\n+8!\n+9!\n",
        {
            "list1": [
                DiffLine("2", 2, 2),
                DiffLine(""),
                DiffLine(""),
                DiffLine(""),
                DiffLine("6", 8, 4),
                DiffLine(""),
                DiffLine(""),
                DiffLine(""),
            ],
            "list2": [
                DiffLine("2!", 3, 2),
                DiffLine("3!", 4, 3),
                DiffLine("4!", 5, 4),
                DiffLine("5!", 6, 5),
                DiffLine("6!", 9, 7),
                DiffLine("7!", 10, 8),
                DiffLine("8!", 11, 9),
                DiffLine("9!", 12, 10),
            ],
        },
    ),
    # 2 blocks. Block 1: 2 minus line, 2 plus line. Block 2: 1 minus line, 2 plus line.
    (
        "@@ -1,5 +1,6 @@\n 1\n-2\n-3\n+2!\n+3!\n \n-4\n+4!\n+5!\n",
        {
            "list1": [
                DiffLine("2", 2, 2),
                DiffLine("3", 3, 3),
                DiffLine("4", 7, 5),
                DiffLine(""),
            ],
            "list2": [
                DiffLine("2!", 4, 2),
                DiffLine("3!", 5, 3),
                DiffLine("4!", 8, 5),
                DiffLine("5!", 9, 6),
            ],
        },
    ),
    # 2 blocks. Block 1: 2 minus line, 2 plus line. Block 2: 1 minus line, 4 plus line.
    (
        "@@ -1,5 +1,8 @@\n 1\n-2\n-3\n+2!\n+3!\n \n-4\n+4!\n+5!\n+6!\n+7!\n",
        {
            "list1": [
                DiffLine("2", 2, 2),
                DiffLine("3", 3, 3),
                DiffLine("4", 7, 5),
                DiffLine(""),
                DiffLine(""),
                DiffLine(""),
            ],
            "list2": [
                DiffLine("2!", 4, 2),
                DiffLine("3!", 5, 3),
                DiffLine("4!", 8, 5),
                DiffLine("5!", 9, 6),
                DiffLine("6!", 10, 7),
                DiffLine("7!", 11, 8),
            ],
        },
    ),
    # 1 block. 2 minus line, 1 plus line
    (
        "@@ -1,3 +1,2 @@\n 1\n-2!\n-3!\n+2\n",
        {
            "list1": [DiffLine("2!", 2, 2), DiffLine("3!", 3, 3)],
            "list2": [DiffLine("2", 4, 2), DiffLine("")],
        },
    ),
    # 1 block. 4 minus line, 1 plus line
    (
        "@@ -1,5 +1,2 @@\n 1\n-2!\n-3!\n-4!\n-5!\n+2\n",
        {
            "list1": [
                DiffLine("2!", 2, 2),
                DiffLine("3!", 3, 3),
                DiffLine("4!", 4, 4),
                DiffLine("5!", 5, 5),
            ],
            "list2": [
                DiffLine("2", 6, 2),
                DiffLine(""),
                DiffLine(""),
                DiffLine(""),
            ],
        },
    ),
    # 2 blocks. Block 1: 2 minus line, 1 plus line. Block 2: 2 minus line, 1 plus line.
    (
        "@@ -1,6 +1,4 @@\n 1\n-2!\n-3!\n+2\n \n-4!\n-5!\n+4\n",
        {
            "list1": [
                DiffLine("2!", 2, 2),
                DiffLine("3!", 3, 3),
                DiffLine("4!", 6, 5),
                DiffLine("5!", 7, 6),
            ],
            "list2": [
                DiffLine("2", 4, 2),
                DiffLine(""),
                DiffLine("4", 8, 4),
                DiffLine(""),
            ],
        },
    ),
    # 2 blocks. Block 1: 4 minus line, 1 plus line. Block 2: 4 minus line, 1 plus line.
    (
        "@@ -1,10 +1,4 @@\n 1\n-2!\n-3!\n-4!\n-5!\n+2\n \n-6!\n-7!\n-8!\n-9!\n+6\n",
        {
            "list1": [
                DiffLine("2!", 2, 2),
                DiffLine("3!", 3, 3),
                DiffLine("4!", 4, 4),
                DiffLine("5!", 5, 5),
                DiffLine("6!", 8, 7),
                DiffLine("7!", 9, 8),
                DiffLine("8!", 10, 9),
                DiffLine("9!", 11, 10),
            ],
            "list2": [
                DiffLine("2", 6, 2),
                DiffLine(""),
                DiffLine(""),
                DiffLine(""),
                DiffLine("6", 12, 4),
                DiffLine(""),
                DiffLine(""),
                DiffLine(""),
            ],
        },
    ),
    # 2 blocks. Block 1: 2 minus line, 2 plus line. Block 2: 2 minus line, 1 plus line.
    (
        "@@ -1,6 +1,5 @@\n 1\n-2!\n-3!\n+2\n+3\n \n-4!\n-5!\n+4\n",
        {
            "list1": [
                DiffLine("2!", 2, 2),
                DiffLine("3!", 3, 3),
                DiffLine("4!", 7, 5),
                DiffLine("5!", 8, 6),
            ],
            "list2": [
                DiffLine("2", 4, 2),
                DiffLine("3", 5, 3),
                DiffLine("4", 9, 5),
                DiffLine(""),
            ],
        },
    ),
    # 2 blocks. Block 1: 2 minus line, 2 plus line. Block 2: 4 minus line, 1 plus line.
    (
        "@@ -1,8 +1,5 @@\n 1\n-2!\n-3!\n+2\n+3\n \n-4!\n-5!\n-6!\n-7!\n+4\n",
        {
            "list1": [
                DiffLine("2!", 2, 2),
                DiffLine("3!", 3, 3),
                DiffLine("4!", 7, 5),
                DiffLine("5!", 8, 6),
                DiffLine("6!", 9, 7),
                DiffLine("7!", 10, 8),
            ],
            "list2": [
                DiffLine("2", 4, 2),
                DiffLine("3", 5, 3),
                DiffLine("4", 11, 5),
                DiffLine(""),
                DiffLine(""),
                DiffLine(""),
            ],
        },
    ),
    # Two separate unified diffs. Block 1: 1 minus line, 3 plus line. Block 2: 1 minus line 1 plus line.
    (
        "@@ -1,2 +1,2 @@\n 1\n-2\n+2!\n+3!\n@@ -10,2 +10,2 @@\n 10\n-11\n+11!",
        {
            "list1": [
                DiffLine("2", 2, 2),
                DiffLine(""),
                DiffLine("11", 7, 11),
            ],
            "list2": [
                DiffLine("2!", 3, 2),
                DiffLine("3!", 4, 3),
                DiffLine("11!", 8, 11),
            ],
        },
    ),
]


@pytest.mark.parametrize("test_input, expected", TEST_UNIFIED_DIFFS)
def test_align_diff_lines(test_input, expected):
    """Tests that lines in unified diff get aligned as expected."""

    line_list1, line_list2 = align_diff_lines(test_input.splitlines())

    assert len(line_list1) == len(expected["list1"])
    assert len(line_list2) == len(expected["list2"])

    for line, expected_line in zip(line_list1, expected["list1"]):
        assert line == expected_line
    for line, expected_line in zip(line_list2, expected["list2"]):
        assert line == expected_line


# -----------------------------------------------------------------------------
# Tests for failures_from_difflines
# -----------------------------------------------------------------------------

TEST_DIFFLINES = [
    (
        {
            "minus_line": DiffLine("example 123"),
            "plus_line": DiffLine("example 456"),
            "flag": get_test_flag(),
        },
        {
            "flagged": [
                make_failure_dict(
                    minus_str="123", plus_str="456", flag=get_test_flag()
                )
            ],
            "unknown": [],
            "minus_unmatched": portion.closedopen(0, 8),
            "plus_unmatched": portion.closedopen(0, 8),
        },
    ),
    (
        {
            "minus_line": DiffLine("123 example"),
            "plus_line": DiffLine("456 example"),
            "flag": get_test_flag(),
        },
        {
            "flagged": [
                make_failure_dict(
                    minus_str="123", plus_str="456", flag=get_test_flag()
                )
            ],
            "unknown": [],
            "minus_unmatched": portion.openclosed(2, 10),
            "plus_unmatched": portion.openclosed(2, 10),
        },
    ),
    (
        {
            "minus_line": DiffLine("123 example 321"),
            "plus_line": DiffLine("456 example 654"),
            "flag": get_test_flag(),
        },
        {
            "flagged": [
                make_failure_dict(
                    minus_str="123", plus_str="456", flag=get_test_flag()
                ),
                make_failure_dict(
                    minus_str="321", plus_str="654", flag=get_test_flag()
                ),
            ],
            "unknown": [],
            "minus_unmatched": portion.open(2, 12),
            "plus_unmatched": portion.open(2, 12),
        },
    ),
]


@pytest.mark.parametrize("test_input, expected", TEST_DIFFLINES)
def test_failures_from_difflines(test_input, expected):
    """Tests that failures are correctly flagged, and intervals are updated correctly"""

    flagged, unknown, minus_unmatched, plus_unmatched = (
        failures_from_difflines(**test_input)
    )

    assert flagged == expected["flagged"]
    assert unknown == expected["unknown"]
    assert minus_unmatched == expected["minus_unmatched"]
    assert plus_unmatched == expected["plus_unmatched"]


# -----------------------------------------------------------------------------
# Tests for make_failure_dict
# -----------------------------------------------------------------------------

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
def test_make_failure_dict(test_input, expected):
    """Tests that the dict is created properly."""

    dict = make_failure_dict(**test_input)

    assert dict == expected


# -----------------------------------------------------------------------------
# Tests for intervals_to_str
# -----------------------------------------------------------------------------

TEST_INTERVALS = [
    (
        {"input_string": "0123456789", "intervals": portion.closed(3, 6)},
        "3456",
    ),
    ({"input_string": "0123456789", "intervals": portion.open(3, 6)}, "45"),
    (
        {"input_string": "0123456789", "intervals": portion.openclosed(3, 6)},
        "456",
    ),
    (
        {"input_string": "0123456789", "intervals": portion.closedopen(3, 6)},
        "345",
    ),
    (
        {
            "input_string": "0123456789",
            "intervals": portion.closed(1, 3) | portion.closed(5, 7),
        },
        "123567",
    ),
    (
        {
            "input_string": "0123456789",
            "intervals": portion.open(1, 3) | portion.open(5, 7),
        },
        "26",
    ),
]


@pytest.mark.parametrize("test_input, expected", TEST_INTERVALS)
def test_intervals_to_str(test_input, expected):
    """Tests that the correct substrings are returned with defined intervals."""

    str = intervals_to_str(**test_input)

    assert str == expected
