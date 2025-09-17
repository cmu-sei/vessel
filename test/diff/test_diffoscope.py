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

from test.fixture import make_test_file_diff
from vessel.diff.helpers.diffoscope import (
    build_diff_lookup,
    build_diffoscope_command,
)
from vessel.diff.helpers.file_diff import FileDiffs


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
            FileDiffs(
                [
                    make_test_file_diff(
                        "source1/rootfs/path1",
                        "source2/rootfs/path1",
                    ),
                    make_test_file_diff(
                        "source1/rootfs/path2",
                        "source2/rootfs/path2",
                    ),
                ]
            ),
            {
                ("path1", "path1"): FileDiffs(
                    [
                        make_test_file_diff(
                            "source1/rootfs/path1",
                            "source2/rootfs/path1",
                        )
                    ]
                ),
                ("path2", "path2"): FileDiffs(
                    [
                        make_test_file_diff(
                            "source1/rootfs/path2",
                            "source2/rootfs/path2",
                        )
                    ]
                ),
            },
        ),
        # One matching path, one mismatched path
        (
            FileDiffs(
                [
                    make_test_file_diff(
                        "source1/rootfs/path1",
                        "source2/rootfs/path1",
                    ),
                    make_test_file_diff(
                        "source1/rootfs/path2",
                        "source2/rootfs/path3",
                    ),
                ]
            ),
            {
                ("path1", "path1"): FileDiffs(
                    [
                        make_test_file_diff(
                            "source1/rootfs/path1", "source2/rootfs/path1"
                        ),
                    ]
                ),
                ("path2", "path3"): FileDiffs(
                    [
                        make_test_file_diff(
                            "source1/rootfs/path2", "source2/rootfs/path3"
                        )
                    ]
                ),
            },
        ),
    ],
)
def test_build_diff_lookup(test_input, expected):
    """Test build_diff_lookup."""
    output = build_diff_lookup(test_input)
    assert output == expected
