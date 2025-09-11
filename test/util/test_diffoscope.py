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

"""Unit test for diffoscope util functions"""

import pytest

from pathlib import Path
from vessel.utils.diffoscope import (
    build_diff_lookup,
    build_diffoscope_command,
    is_abs_path,
)


def test_build_diffoscope_command():
    output_dir = "/tmp"
    output_file = "diff.json"
    path1 = "/test_path/file1"
    path2 = "/test_path/file2"

    def make_expected_output(profile_enabled):
        expected = [
            "diffoscope",
            "--json",
            f"{output_dir}/{output_file}",
            "--new-file",
            path1,
            path2,
            "--exclude-directory-metadata",
            "no",
        ]
        if profile_enabled:
            expected.extend(["--profile", f"{output_dir}/profile.txt"])
        expected.extend(
            [
                "--exclude-command",
                r"^readelf.*",
                "--exclude-command",
                r"^objdump.*",
                "--exclude-command",
                r"^strings.*",
                "--exclude-command",
                r"^xxd.*",
            ]
        )
        return expected

    # without profile
    assert build_diffoscope_command(
        output_dir, output_file, path1, path2, "file", profile_enabled=False
    ) == make_expected_output(False)

    # with profile
    assert build_diffoscope_command(
        output_dir, output_file, path1, path2, "file", profile_enabled=True
    ) == make_expected_output(True)


@pytest.mark.parametrize(
    "test_input, expected",
    [
        # Two matching paths
        (
            [
                {
                    "source1": "source1/rootfs/path1",
                    "source2": "source2/rootfs/path1",
                    "unified_diff_id": "",
                    "unified_diff": "",
                },
                {
                    "source1": "source1/rootfs/path2",
                    "source2": "source2/rootfs/path2",
                    "unified_diff_id": "",
                    "unified_diff": "",
                },
            ],
            {
                ("path1", "path1"): [
                    {
                        "source1": "source1/rootfs/path1",
                        "source2": "source2/rootfs/path1",
                        "unified_diff_id": "",
                        "unified_diff": "",
                    },
                ],
                ("path2", "path2"): [
                    {
                        "source1": "source1/rootfs/path2",
                        "source2": "source2/rootfs/path2",
                        "unified_diff_id": "",
                        "unified_diff": "",
                    },
                ],
            },
        ),
        # One matching path, one mismatched path
        (
            [
                {
                    "source1": "source1/rootfs/path1",
                    "source2": "source2/rootfs/path1",
                    "unified_diff_id": "",
                    "unified_diff": "",
                },
                {
                    "source1": "source1/rootfs/path2",
                    "source2": "source2/rootfs/path3",
                    "unified_diff_id": "",
                    "unified_diff": "",
                },
            ],
            {
                ("path1", "path1"): [
                    {
                        "source1": "source1/rootfs/path1",
                        "source2": "source2/rootfs/path1",
                        "unified_diff_id": "",
                        "unified_diff": "",
                    },
                ],
                ("path2", "path3"): [
                    {
                        "source1": "source1/rootfs/path2",
                        "source2": "source2/rootfs/path3",
                        "unified_diff_id": "",
                        "unified_diff": "",
                    },
                ],
            },
        ),
    ],
)
def test_build_diff_lookup(test_input, expected):
    """Test build_diff_lookup."""
    output = build_diff_lookup(test_input)
    assert output == expected


@pytest.mark.parametrize(
    "test_input, expected",
    [
        # Valid absolute path as Path
        (
            Path("/srv/local/test"),
            True
        ),
        # Valid absoute path as string
        (
            "/srv/local/test",
            True,
        ),
        # Non-absolute path as Path
        (
            Path("srv/local/test"),
            False,
        ),
        # Non-absolute path as string
        (
            "srv/local/test",
            False,
        ),
        # Random string
        (
            "not a path",
            False,
        ),
    ]
)
def test_is_abs_path(test_input, expected):
    """Test is_abs_path."""
    assert is_abs_path(test_input) == expected