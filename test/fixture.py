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
"""Fixtures for all unit tests."""

from vessel.utils.flag import Flag


def get_test_flag():
    return Flag(
        flag_id="test_flag",
        description="test flag",
        filepath=".*",
        filetype=".*",
        command=".*",
        comment=".*",
        indiff=r"\d+",
        severity="Low",
        metadata=False,
    )


def get_test_diffoscope_output():
    return {
        "diffoscope-json-version": 1,
        "source1": "/example_path1/rootfs",
        "source2": "/example_path2/rootfs",
        "unified_diff": None,
        "details": [
            {
                "source1": "/example_path1/rootfs/app",
                "source2": "/example_path2/rootfs/app",
                "unified_diff": None,
                "details": [
                    {
                        "source1": "stat {}",
                        "source2": "stat {}",
                        "unified_diff": "@@ -1,8 +1,8 @@\n \n   Size: 4096      \tBlocks: 8          IO Block: 4096   directory\n Device: 0,72\tLinks: 3\n Access: (0755/drwxr-xr-x)  Uid: (    0/    root)   Gid: (    0/    root)\n \n+Modify: 2024-12-03 21:14:59.000000000 +0000\n-Modify: 2024-12-03 20:54:07.000000000 +0000\n \n \n",
                    },
                    {
                        "source1": "/example_path1/rootfs/app/cmd",
                        "source2": "/example_path2/rootfs/app/cmd",
                        "unified_diff": None,
                        "details": [
                            {
                                "source1": "stat {}",
                                "source2": "stat {}",
                                "unified_diff": "@@ -1,8 +1,8 @@\n \n   Size: 4096      \tBlocks: 8          IO Block: 4096   directory\n Device: 0,72\tLinks: 3\n Access: (0755/drwxr-xr-x)  Uid: (    0/    root)   Gid: (    0/    root)\n \n-Modify: 2024-12-03 20:54:07.000000000 +0000\n+Modify: 2024-12-03 21:14:59.000000000 +0000\n \n \n",
                            },
                            {
                                "source1": "/example_path1/rootfs/app/cmd/acmesolver",
                                "source2": "/example_path2/rootfs/app/cmd/acmesolver",
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
                "source1": "/example_path1/rootfs/licenses",
                "source2": "/example_path2/rootfs/licenses",
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
