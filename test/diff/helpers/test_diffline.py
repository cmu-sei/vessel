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

"""Unit tests for DiffLine"""

from vessel.diff.helpers.diffline import DiffLine


def test_diffline_init_and_intervals():
    diffline = DiffLine("hello", diff_line_number=5, file_line_number=20)

    assert diffline.text == "hello"
    assert diffline.diff_line_number == 5
    assert diffline.file_line_number == 20
    assert diffline.unmatched_intervals.lower == 0
    assert diffline.unmatched_intervals.upper == len("hello") - 1


def test_diffline_equality_with_same_values():
    diffline1 = DiffLine("same", diff_line_number=1, file_line_number=2)
    diffline2 = DiffLine("same", diff_line_number=1, file_line_number=2)
    assert diffline1 == diffline2


def test_diffline_equality_with_differernt_values():
    cur_diffline = DiffLine(
        "different", diff_line_number=1, file_line_number=1
    )
    assert cur_diffline != DiffLine(
        "hello", diff_line_number=1, file_line_number=1
    )
    assert cur_diffline != DiffLine(
        "different", diff_line_number=2, file_line_number=1
    )
