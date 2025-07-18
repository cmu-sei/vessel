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

from test.fixture import get_test_diffoscope_output, get_test_flag
from vessel.utils.diffoscope import (
    build_diff_lookup,
    build_diffoscope_command,
    parse_diffoscope_output,
)


def test_build_diffoscope_command():
    output_dir = "/tmp"
    output_file = "diff.json"
    path1 = "/test_path/file1"
    path2 = "/test_path/file2"
    exclude_params = [
        "--exclude-directory-metadata",
        "no",
        "--profile",
        f"{output_dir}/profile.txt",
        "--exclude-command",
        r"^readelf.*",
        "--exclude-command",
        r"^objdump.*",
        "--exclude-command",
        r"^strings.*",
        "--exclude-command",
        r"^xxd.*",
    ]

    expected_cmd_file = [
        "diffoscope",
        "--json",
        "/tmp/diff.json",
        "--new-file",
        path1,
        path2,
    ]
    expected_cmd_file.extend(exclude_params)
    assert (
        build_diffoscope_command(output_dir, output_file, path1, path2, "file")
        == expected_cmd_file
    )

    expected_cmd_image = [
        "diffoscope",
        "--json",
        f"{output_dir}/{output_file}",
        path1,
        path2,
    ]
    expected_cmd_image.extend(exclude_params)
    assert (
        build_diffoscope_command(
            output_dir, output_file, path1, path2, "image"
        )
        == expected_cmd_image
    )


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


def test_parse_diffoscope_output_debug():
    test_diff = get_test_diffoscope_output()
    test_flag = get_test_flag()

    (
        unknown_failures,
        trivial_failures,
        nontrivial_failures,
        diff_list,
        files_summary,
        checksum_summary,
    ) = parse_diffoscope_output(test_diff, [test_flag])

    assert unknown_failures == 0
    assert trivial_failures > 0
    assert nontrivial_failures == 0
    assert len(diff_list) > 0
    assert "flagged_failures" in diff_list[0]
    assert diff_list[0]["flagged_failures"][0]["id"] == "test_flag"
    assert len(files_summary) > 0
    assert checksum_summary["total_common_files"] == 0
