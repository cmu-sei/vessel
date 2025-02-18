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

from vessel.utils.unified_diff import equal_entry_list, parse_unified_diff_header, DiffLine, align_diff_lines

import pytest

# TODO : Does this need to handle DiffLine objects? the object compare breaks on hashes of the obj
# (
#     { "list1": [DiffLine("line1", None, None), DiffLine("line2", None, None)], "list2": [DiffLine("line3", None, None)], "fillValue": DiffLine("", None, None)},
#     { "list1": [DiffLine("line1", None, None), DiffLine("line2", None, None)], "list2": [DiffLine("line3", None, None), DiffLine("", None, None)]}
# ),
TEST_LISTS = [
    (
        { "list1": [1,2,3],    "list2": [1,2,3,4], "fillValue": -1},
        { "list1": [1,2,3,-1], "list2": [1,2,3,4]}
    ),
    (
        { "list1": [1,2,3,4], "list2": [1,2,3], "fillValue": -1},
        { "list1": [1,2,3,4], "list2": [1,2,3,-1]}
    ),
    (
        { "list1": [1,2,3],          "list2": [1,2,3,4,5,6], "fillValue": -1},
        { "list1": [1,2,3,-1,-1,-1], "list2": [1,2,3,4,5,6]}
    ),
    (
        { "list1": [1,2,3,4,5,6], "list2": [1,2,3], "fillValue": -1},
        { "list1": [1,2,3,4,5,6], "list2": [1,2,3,-1,-1,-1]}
    ),
    (
        { "list1": [], "list2": [], "fillValue": -1},
        { "list1": [], "list2": []}
    ),
    (
        { "list1": [],   "list2": [1], "fillValue": -1},
        { "list1": [-1], "list2": [1]}
    ),
    (
        { "list1": [1], "list2": [], "fillValue": -1},
        { "list1": [1], "list2": [-1]}
    ),
    (
        { "list1": [],         "list2": [1,2,3], "fillValue": -1},
        { "list1": [-1,-1,-1], "list2": [1,2,3]}
    ),
    (
        { "list1": [1,2,3], "list2": [], "fillValue": -1},
        { "list1": [1,2,3], "list2": [-1,-1,-1]}
    ),
]

TEST_UNIFIED_DIFF_HEADERS = [
    ("@@ -8,13 +15,13 @@", (8, 15)),
    ("@@ -0,0 +1 @@", (0, 1)),
    ("@@ -1 +0,0 @@", (1, 0))
]

TEST_UNIFIED_DIFFS = [
    (
        "@@ -1,2 +1,3 @@\n 1\n-2\n+2!\n+3!\n",
        ([DiffLine("2", 2, 2), DiffLine("")], [DiffLine("2!", 2, 3), DiffLine("3!", 4, 3)])
    ),
    (
        "@@ -1,3 +1,2 @@\n 1\n-2!\n-3!\n+2\n",
        ([DiffLine("2!", 2, 2), DiffLine("3!", 3, 3)], [DiffLine("2", 4, 2), DiffLine("")])
    )
]

"""Tests for Unified Diff functions."""

# def test_Diff():
#     assert False

# def test_DiffLine():
#     assert False

@pytest.mark.parametrize("test_input, expected", TEST_LISTS)
def test_equal_entry_list(test_input: dict, expected: dict):
    """Tests that inputted lists are returned equal length with the correct fill value."""

    equal_list1, equal_list2 = equal_entry_list(test_input["list1"], test_input["list2"], test_input["fillValue"])

    assert equal_list1 == expected["list1"]
    assert equal_list2 == expected["list2"]

@pytest.mark.parametrize("test_input, expected", TEST_UNIFIED_DIFF_HEADERS)
def test_parse_unified_diff_header(test_input: str, expected: tuple[int, int]):
    """Tests that the unified diff header is parsed correctly to return start lines of the diffs."""

    line_num1, line_num2 = parse_unified_diff_header(test_input)

    assert (line_num1, line_num2) == expected

@pytest.mark.parametrize("test_input, expected", TEST_UNIFIED_DIFFS)
def test_align_diff_lines(test_input, expected):
    """Tests that lines in unified diff get aligned as expected."""

    # TODO : Is it wrong to do splitlines here? Nice to save space in the test list
    line_list1, line_list2 = align_diff_lines(test_input.splitlines())

    print(line_list1[0].diff_line_number)
    print(expected[0][0].diff_line_number)

    for line, expected_line in zip(line_list1, expected[0]):
        print(line.text + " " + expected_line.text)
        print(line.text + " " + expected_line.text)
        assert line.text == expected_line.text
        assert line.diff_line_number == expected_line.diff_line_number
        assert line.file_line_number == expected_line.file_line_number