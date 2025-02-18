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
        { "list1": [1,2],    "list2": [1,2,3], "fillValue": -1},
        { "list1": [1,2,-1], "list2": [1,2,3]}
    ),
    (
        { "list1": [1,2],          "list2": [1,2,3,4,5], "fillValue": -1},
        { "list1": [1,2,-1,-1,-1], "list2": [1,2,3,4,5]}
    ),
    (
        { "list1": [1,2,3], "list2": [1,2], "fillValue": -1},
        { "list1": [1,2,3], "list2": [1,2,-1]}
    ),
    (
        { "list1": [1,2,3,4,5], "list2": [1,2], "fillValue": -1},
        { "list1": [1,2,3,4,5], "list2": [1,2,-1,-1,-1]}
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
        { "list1": [],      "list2": [1,2], "fillValue": -1},
        { "list1": [-1,-1], "list2": [1,2]}
    ),
    (
        { "list1": [1], "list2": [], "fillValue": -1},
        { "list1": [1], "list2": [-1]}
    ),
    (
        { "list1": [1,2], "list2": [], "fillValue": -1},
        { "list1": [1,2], "list2": [-1,-1]}
    ),
]

TEST_UNIFIED_DIFF_HEADERS = [
    ("@@ -8,13 +15,13 @@", (8, 15)),
    ("@@ -0,0 +1 @@", (0, 1)),
    ("@@ -1 +0,0 @@", (1, 0))
]

TEST_UNIFIED_DIFFS = [
    # 1 block. 1 minus line, 2 plus line
    (
        "@@ -1,2 +1,3 @@\n 1\n-2\n+2!\n+3!\n",
        ([DiffLine("2", 2, 2), DiffLine("")], [DiffLine("2!", 3, 2), DiffLine("3!", 4, 3)])
    ),
    # 1 block. 1 minus line, 4 plus line
    (
        "@@ -1,2 +1,5 @@\n 1\n-2\n+2!\n+3!\n+4!\n+5!\n",
        ([DiffLine("2", 2, 2), DiffLine(""), DiffLine(""), DiffLine("")], [DiffLine("2!", 3, 2), DiffLine("3!", 4, 3), DiffLine("4!", 5, 4), DiffLine("5!", 6, 5)])
    ),
    # 2 blocks. Block 1: 1 minus line, 2 plus line. Block 2: 1 minus line, 2 plus line.
    (
        "@@ -1,4 +1,6 @@\n 1\n-2\n+2!\n+3!\n \n-4\n+4!\n+5!\n",
        ([DiffLine("2", 2, 2), DiffLine(""), DiffLine("4", 6, 4), DiffLine("")], [DiffLine("2!", 3, 2), DiffLine("3!", 4, 3), DiffLine("4!", 7, 5), DiffLine("5!", 8, 6)])
    ),
    # 2 blocks. Block 1: 1 minus line, 4 plus line. Block 2: 1 minus line, 4 plus line.
    (
        "@@ -1,4 +1,10 @@\n 1\n-2\n+2!\n+3!\n+4!\n+5!\n \n-6\n+6!\n+7!\n+8!\n+9!\n",
        ([DiffLine("2", 2, 2), DiffLine(""), DiffLine(""), DiffLine(""), DiffLine("6", 8, 4), DiffLine(""), DiffLine(""), DiffLine("")], [DiffLine("2!", 3, 2), DiffLine("3!", 4, 3), DiffLine("4!", 5, 4), DiffLine("5!", 6, 5), DiffLine("6!", 9, 7), DiffLine("7!", 10, 8), DiffLine("8!", 11, 9), DiffLine("9!", 12, 10)])
    ),
    # 2 blocks. Block 1: 2 minus line, 2 plus line. Block 2: 1 minus line, 2 plus line.
    (
        "@@ -1,5 +1,6 @@\n 1\n-2\n-3\n+2!\n+3!\n \n-4\n+4!\n+5!\n",
        ([DiffLine("2", 2, 2), DiffLine("3", 3, 3), DiffLine("4", 7, 5), DiffLine("")], [DiffLine("2!", 4, 2), DiffLine("3!", 5, 3), DiffLine("4!", 8, 5), DiffLine("5!", 9, 6)])
    ),
    # 2 blocks. Block 1: 2 minus line, 2 plus line. Block 2: 1 minus line, 4 plus line.
    (
        "@@ -1,5 +1,8 @@\n 1\n-2\n-3\n+2!\n+3!\n \n-4\n+4!\n+5!\n+6!\n+7!\n",
        ([DiffLine("2", 2, 2), DiffLine("3", 3, 3), DiffLine("4", 7, 5), DiffLine(""), DiffLine(""), DiffLine("")], [DiffLine("2!", 4, 2), DiffLine("3!", 5, 3), DiffLine("4!", 8, 5), DiffLine("5!", 9, 6), DiffLine("6!", 10, 7), DiffLine("7!", 11, 8)])
    ),
    # 1 block. 2 minus line, 1 plus line
    (
        "@@ -1,3 +1,2 @@\n 1\n-2!\n-3!\n+2\n",
        ([DiffLine("2!", 2, 2), DiffLine("3!", 3, 3)], [DiffLine("2", 4, 2), DiffLine("")])
    ),
    # 1 block. 4 minus line, 1 plus line
    (
        "@@ -1,5 +1,2 @@\n 1\n-2!\n-3!\n-4!\n-5!\n+2\n",
        ([DiffLine("2!", 2, 2), DiffLine("3!", 3, 3), DiffLine("4!", 4, 4), DiffLine("5!", 5, 5)], [DiffLine("2", 6, 2), DiffLine(""), DiffLine(""), DiffLine("")])
    ),
    # 2 blocks. Block 1: 2 minus line, 1 plus line. Block 2: 2 minus line, 1 plus line.
    (
        "@@ -1,6 +1,4 @@\n 1\n-2!\n-3!\n+2\n \n-4!\n-5!\n+4\n",
        ([DiffLine("2!", 2, 2), DiffLine("3!", 3, 3), DiffLine("4!", 6, 5), DiffLine("5!", 7, 6)], [DiffLine("2", 4, 2), DiffLine(""), DiffLine("4", 8, 4), DiffLine("")])
    ),
    # 2 blocks. Block 1: 4 minus line, 1 plus line. Block 2: 4 minus line, 1 plus line.
    (
        "@@ -1,10 +1,4 @@\n 1\n-2!\n-3!\n-4!\n-5!\n+2\n \n-6!\n-7!\n-8!\n-9!\n+6\n",
        ([DiffLine("2!", 2, 2), DiffLine("3!", 3, 3), DiffLine("4!", 4, 4), DiffLine("5!", 5, 5), DiffLine("6!", 8, 7), DiffLine("7!", 9, 8), DiffLine("8!", 10, 9), DiffLine("9!", 11, 10)], [DiffLine("2", 6, 2), DiffLine(""), DiffLine(""), DiffLine(""), DiffLine("6", 12, 4), DiffLine(""), DiffLine(""), DiffLine("")])
    ),
    # 2 blocks. Block 1: 2 minus line, 2 plus line. Block 2: 2 minus line, 1 plus line.
    (
        "@@ -1,6 +1,5 @@\n 1\n-2!\n-3!\n+2\n+3\n \n-4!\n-5!\n+4\n",
        ([DiffLine("2!", 2, 2), DiffLine("3!", 3, 3), DiffLine("4!", 7, 5), DiffLine("5!", 8, 6)], [DiffLine("2", 4, 2), DiffLine("3", 5, 3), DiffLine("4", 9, 5), DiffLine("")])
    ),
    # 2 blocks. Block 1: 2 minus line, 2 plus line. Block 2: 4 minus line, 1 plus line.
    (
        "@@ -1,8 +1,5 @@\n 1\n-2!\n-3!\n+2\n+3\n \n-4!\n-5!\n-6!\n-7!\n+4\n",
        ([DiffLine("2!", 2, 2), DiffLine("3!", 3, 3), DiffLine("4!", 7, 5), DiffLine("5!", 8, 6), DiffLine("6!", 9, 7), DiffLine("7!", 10, 8)], [DiffLine("2", 4, 2), DiffLine("3", 5, 3), DiffLine("4", 11, 5), DiffLine(""), DiffLine(""), DiffLine("")])
    ),
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

    assert len(line_list1) == len(expected[0])
    assert len(line_list2) == len(expected[1])

    for line, expected_line in zip(line_list1, expected[0]):
        assert line.text == expected_line.text
        assert line.diff_line_number == expected_line.diff_line_number
        assert line.file_line_number == expected_line.file_line_number

    for line, expected_line in zip(line_list2, expected[1]):
        assert line.diff_line_number == expected_line.diff_line_number
        assert line.file_line_number == expected_line.file_line_number