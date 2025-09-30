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
    DiffoscopeParser,
    build_diff_lookup,
    build_diffoscope_command,
)
from vessel.diff.helpers.failure import FailureSummary
from vessel.diff.helpers.file_diff import FileDiff, FileDiffs


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


def generate_detail():
    """Helper to generate a diffoscope dict with valid unified diff"""
    unified_diff = "\n".join(
        [
            "@@ -1,8 +1,8 @@",
            " ",
            "   Size: 4096      \tBlocks: 8          IO Block: 4096   directory",
            " Device: 0,320\tLinks: 49",
            " Access: (0755/drwxr-xr-x)  Uid: (    0/    root)   Gid: (    0/    root)",
            " ",
            "+Modify: 2025-08-08 17:43:33.000000000 +0000",
            "-Modify: 2025-08-08 22:07:31.000000000 +0000",
            " ",
        ]
    )
    return {
        "source1": "/tmp/tmpesh6umrr/umoci-unpack-output_2025-08-08_15-26-31.tar.latest/rootfs/usr/bin",
        "source2": "/tmp/tmpesh6umrr/umoci-unpack-output_2025-08-08_11-01-49.tar.latest/rootfs/usr/bin",
        "unified_diff": unified_diff,
        "comments": ["Similarity: 0.90625%"],
        "command": "stat {}",
    }


def test_parser_initialize_with_empty_json():
    empty_json = {"unified_diff": None, "details": []}
    parser = DiffoscopeParser(empty_json, flags=[])
    assert isinstance(parser.failure_summary, FailureSummary)
    assert parser.failure_summary.unknown_failure_count == 0
    assert parser.failure_summary.trivial_failure_count == 0
    assert parser.failure_summary.nontrivial_failure_count == 0
    assert isinstance(parser.diff_list, FileDiffs)
    assert len(parser.diff_list.diffs) == 0


def test_parse_detail_adds_file_diff():
    empty_json = {"unified_diff": None, "details": []}
    parser = DiffoscopeParser(empty_json, flags=[])
    detail = generate_detail()
    parser._parse_detail(detail)
    assert len(parser.diff_list.diffs) == 1
    file_diff = parser.diff_list.diffs[0]
    assert isinstance(file_diff, FileDiff)
    assert "usr/bin" in file_diff.source1
    assert "usr/bin" in file_diff.source2
    assert any("Modify:" in line for line in file_diff.unified_diff)
    assert "Similarity: 0.90625%" in file_diff.comments


def test_recurse_invoke_parse_detail(monkeypatch):
    """
    Here we want to check _recurse actually calls _parse_detail when provided a diff
    But we just want to test the flow, we utilize monkeypatch and a spy function to
    make sure the _parse_detail was called
    """
    called = {}

    def record_call(detail, *args, **kwargs):
        called["seen"] = detail

    empty_json = {"unified_diff": None, "details": []}
    parser = DiffoscopeParser(empty_json, flags=[])
    monkeypatch.setattr(parser, "_parse_detail", record_call)
    parser._recurse(generate_detail())
    assert "seen" in called


def test_recurse_visits_children(monkeypatch):
    """
    Same as above, goes into children nodes and parse each one
    Make sure all the sources are visited
    """
    visited = []

    def record_parse_detail(detail, *args, **kwargs):
        visited.append(detail["source1"])

    empty_json = {"unified_diff": None, "details": []}
    parser = DiffoscopeParser(empty_json, flags=[])
    monkeypatch.setattr(parser, "_parse_detail", record_parse_detail)

    parent = {
        "source1": "/tmp/tmpesh6umrr/umoci-unpack-output_2025-08-08_15-26-31.tar.latest/rootfs/usr/lib",
        "source2": "/tmp/tmpesh6umrr/umoci-unpack-output_2025-08-08_11-01-49.tar.latest/rootfs/usr/lib",
        "unified_diff": None,
        "details": [
            {
                "source1": "/tmp/tmpesh6umrr/umoci-unpack-output_2025-08-08_15-26-31.tar.latest/rootfs/usr/lib/.build-id/1a",
                "source2": "/tmp/tmpesh6umrr/umoci-unpack-output_2025-08-08_11-01-49.tar.latest/rootfs/usr/lib/.build-id/1a",
                "unified_diff": "\n".join(
                    [
                        "@@ -1,8 +1,8 @@",
                        " ",
                        "   Size: 4096      \tBlocks: 8          IO Block: 4096   directory",
                        " Device: 0,320\tLinks: 49",
                        " Access: (0755/drwxr-xr-x)  Uid: (    0/    root)   Gid: (    0/    root)",
                        " ",
                        "+Modify: 2025-08-08 19:26:39.000000000 +0000",
                        "-Modify: 2025-08-08 15:02:20.000000000 +0000",
                        " ",
                    ]
                ),
                "command": "stat {}",
                "comments": ["Similarity: 0.90625%"],
            },
            {
                "source1": "/tmp/tmpesh6umrr/umoci-unpack-output_2025-08-08_15-26-31.tar.latest/rootfs/usr/lib/.build-id/83",
                "source2": "/tmp/tmpesh6umrr/umoci-unpack-output_2025-08-08_11-01-49.tar.latest/rootfs/usr/lib/.build-id/83",
                "unified_diff": "\n".join(
                    [
                        "@@ -1,8 +1,8 @@",
                        " ",
                        "   Size: 4096      \tBlocks: 8          IO Block: 4096   directory",
                        " Device: 0,320\tLinks: 49",
                        " Access: (0755/drwxr-xr-x)  Uid: (    0/    root)   Gid: (    0/    root)",
                        " ",
                        "+Modify: 2025-08-08 19:26:38.000000000 +0000",
                        "-Modify: 2025-08-08 15:02:20.000000000 +0000",
                        " ",
                    ]
                ),
                "command": "stat {}",
                "comments": ["Similarity: 0.90625%"],
            },
        ],
    }

    parser._recurse(parent)

    assert any(
        "/tmp/tmpesh6umrr/umoci-unpack-output_2025-08-08_15-26-31.tar.latest/rootfs/usr/lib/.build-id/1a"
        in path
        for path in visited
    )
    assert any(
        "/tmp/tmpesh6umrr/umoci-unpack-output_2025-08-08_15-26-31.tar.latest/rootfs/usr/lib/.build-id/83"
        in path
        for path in visited
    )
