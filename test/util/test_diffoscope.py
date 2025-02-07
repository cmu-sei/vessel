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

from vessel.utils.diffoscope import (
    build_diffoscope_command,
    parse_diffoscope_output,
)
from vessel.utils.flag import Flag


def test_build_diffoscope_command():
    output_dir = "/tmp"
    output_file = "diff.json"
    path1 = "/test_path//file1"
    path2 = "/test_path/file2"

    expected_cmd_file = [
        "diffoscope",
        "--json",
        "/tmp/diff.json",
        "--new-file",
        "/test_path//file1",
        "/test_path/file2",
    ]
    assert (
        build_diffoscope_command(output_dir, output_file, path1, path2, "file")
        == expected_cmd_file
    )

    expected_cmd_image = [
        "diffoscope",
        "--json",
        "/tmp/diff.json",
        "/test_path//file1",
        "/test_path/file2",
    ]
    assert (
        build_diffoscope_command(
            output_dir, output_file, path1, path2, "image"
        )
        == expected_cmd_image
    )


def test_parse_diffoscope_output_debug():
    test_diff = {
        "diffoscope-json-version": 1,
        "source1": "/tmp/tmp902i7bz7/umoci-unpack-cert-manager-acmesolver.2024-12-03_15-53-00/rootfs",
        "source2": "/tmp/tmp902i7bz7/umoci-unpack-cert-manager-acmesolver.2024-12-03_16-13-42/rootfs",
        "unified_diff": None,
        "details": [
            {
                "source1": "/tmp/tmp902i7bz7/umoci-unpack-cert-manager-acmesolver.2024-12-03_15-53-00/rootfs/app",
                "source2": "/tmp/tmp902i7bz7/umoci-unpack-cert-manager-acmesolver.2024-12-03_16-13-42/rootfs/app",
                "unified_diff": None,
                "details": [
                    {
                        "source1": "stat {}",
                        "source2": "stat {}",
                        "unified_diff": "@@ -1,8 +1,8 @@\n \n   Size: 4096      \tBlocks: 8          IO Block: 4096   directory\n Device: 0,72\tLinks: 3\n Access: (0755/drwxr-xr-x)  Uid: (    0/    root)   Gid: (    0/    root)\n \n+Modify: 2024-12-03 21:14:59.000000000 +0000\n-Modify: 2024-12-03 20:54:07.000000000 +0000\n \n \n",
                    },
                    {
                        "source1": "/tmp/tmp902i7bz7/umoci-unpack-cert-manager-acmesolver.2024-12-03_15-53-00/rootfs/app/cmd",
                        "source2": "/tmp/tmp902i7bz7/umoci-unpack-cert-manager-acmesolver.2024-12-03_16-13-42/rootfs/app/cmd",
                        "unified_diff": None,
                        "details": [
                            {
                                "source1": "stat {}",
                                "source2": "stat {}",
                                "unified_diff": "@@ -1,8 +1,8 @@\n \n   Size: 4096      \tBlocks: 8          IO Block: 4096   directory\n Device: 0,72\tLinks: 3\n Access: (0755/drwxr-xr-x)  Uid: (    0/    root)   Gid: (    0/    root)\n \n-Modify: 2024-12-03 20:54:07.000000000 +0000\n+Modify: 2024-12-03 21:14:59.000000000 +0000\n \n \n",
                            },
                            {
                                "source1": "/tmp/tmp902i7bz7/umoci-unpack-cert-manager-acmesolver.2024-12-03_15-53-00/rootfs/app/cmd/acmesolver",
                                "source2": "/tmp/tmp902i7bz7/umoci-unpack-cert-manager-acmesolver.2024-12-03_16-13-42/rootfs/app/cmd/acmesolver",
                                "unified_diff": None,
                                "details": [
                                    {
                                        "source1": "stat {}",
                                        "source2": "stat {}",
                                        "unified_diff": "@@ -1,8 +1,8 @@\n \n   Size: 4096      \tBlocks: 8          IO Block: 4096   directory\n Device: 0,72\tLinks: 2\n Access: (0755/drwxr-xr-x)  Uid: (    0/    root)   Gid: (    0/    root)\n \n+Modify: 2024-12-03 21:14:59.000000000 +0000\n-Modify: 2024-12-03 20:54:07.000000000 +0000\n \n \n",
                                    },
                                    {
                                        "source1": "stat {}",
                                        "source2": "stat {}",
                                        "unified_diff": "@@ -1,8 +1,8 @@\n \n   Size: 4096      \tBlocks: 8          IO Block: 4096   directory\n Device: 0,72\tLinks: 2\n Access: (0755/drwxr-xr-x)  Uid: (    0/    root)   Gid: (    0/    root)\n \n-Modify: 2024-12-03 20:54:07.000000000 +0000\n+Modify: 2024-12-03 21:14:59.000000000 +0000\n \n \n",
                                    },
                                ],
                            },
                            {
                                "source1": "stat {}",
                                "source2": "stat {}",
                                "unified_diff": "@@ -1,8 +1,8 @@\n \n   Size: 4096      \tBlocks: 8          IO Block: 4096   directory\n Device: 0,72\tLinks: 3\n Access: (0755/drwxr-xr-x)  Uid: (    0/    root)   Gid: (    0/    root)\n \n+Modify: 2024-12-03 21:14:59.000000000 +0000\n-Modify: 2024-12-03 20:54:07.000000000 +0000\n \n \n",
                            },
                        ],
                    },
                    {
                        "source1": "stat {}",
                        "source2": "stat {}",
                        "unified_diff": "@@ -1,8 +1,8 @@\n \n   Size: 4096      \tBlocks: 8          IO Block: 4096   directory\n Device: 0,72\tLinks: 3\n Access: (0755/drwxr-xr-x)  Uid: (    0/    root)   Gid: (    0/    root)\n \n-Modify: 2024-12-03 20:54:07.000000000 +0000\n+Modify: 2024-12-03 21:14:59.000000000 +0000\n \n \n",
                    },
                ],
            },
            {
                "source1": "/tmp/tmp902i7bz7/umoci-unpack-cert-manager-acmesolver.2024-12-03_15-53-00/rootfs/licenses",
                "source2": "/tmp/tmp902i7bz7/umoci-unpack-cert-manager-acmesolver.2024-12-03_16-13-42/rootfs/licenses",
                "unified_diff": None,
                "details": [
                    {
                        "source1": "stat {}",
                        "source2": "stat {}",
                        "unified_diff": "@@ -1,8 +1,8 @@\n \n   Size: 4096      \tBlocks: 8          IO Block: 4096   directory\n Device: 0,72\tLinks: 2\n Access: (0755/drwxr-xr-x)  Uid: (    0/    root)   Gid: (    0/    root)\n \n+Modify: 2024-12-03 21:15:00.000000000 +0000\n-Modify: 2024-12-03 20:54:07.000000000 +0000\n \n \n",
                    },
                    {
                        "source1": "stat {}",
                        "source2": "stat {}",
                        "unified_diff": "@@ -1,8 +1,8 @@\n \n   Size: 4096      \tBlocks: 8          IO Block: 4096   directory\n Device: 0,72\tLinks: 2\n Access: (0755/drwxr-xr-x)  Uid: (    0/    root)   Gid: (    0/    root)\n \n-Modify: 2024-12-03 20:54:07.000000000 +0000\n+Modify: 2024-12-03 21:15:00.000000000 +0000\n \n \n",
                    },
                ],
            },
        ],
    }

    test_flag = Flag(
        flag_id="test_flag",
        description="test flag",
        filepath=".",
        filetype=".",
        command=".",
        comment=".",
        indiff=r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{9}",
    )

    unknown_issues, flagged_issues, diff_list = parse_diffoscope_output(
        test_diff, [test_flag]
    )

    assert flagged_issues > 0
    assert len(diff_list) > 0
    assert "flagged_issues" in diff_list[0]
    assert diff_list[0]["flagged_issues"][0]["id"] == "test_flag"
