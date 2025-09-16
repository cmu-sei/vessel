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
"""Tests for FileDiff classes."""

import pytest

from vessel.diff.helpers.file_diff import FileDiff

# -----------------------------------------------------------------------------
# Tests for FileDiff
# -----------------------------------------------------------------------------

TEST_DIFF_CLASS_OBJECTS = [
    (
        FileDiff(
            "src1",
            "src2",
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
def test_diff_to_dict(test_input, expected):
    """Ensures FileDiff properly converts to a dict"""

    dict = test_input.to_dict()

    assert dict == expected
