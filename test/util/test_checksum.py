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

"""Unit test for checksum util functions"""

import pytest
import re

from vessel.utils.checksum import FileHash, summarize_checksums, classify_checksum_mismatches, hash_folder_contents

# @pytest.mark.parametrize(
#     "test, expected",
#     [
#         (

#         )
#     ]
# )
# def test_hash_folder_contents():
#     pass


@pytest.mark.parametrize(
    "test_input, expected",
    [
        # Two files, two matches
        (
            {
                "folder_path1": "folder_path1",
                "hashed_files1": {
                    "filepath1": FileHash("filepath1", "ASCII text", "filehash1"),
                    "filepath2": FileHash("filepath2", "ASCII text", "filehash2"),
                },
                "folder_path2": "folder_path2",
                "hashed_files2": {
                    "filepath1": FileHash("filepath1", "ASCII text", "filehash1"),
                    "filepath2": FileHash("filepath2", "ASCII text", "filehash2"),
                },
            },
            {
                "image1": "folder_path1",
                "image2": "folder_path2",
                "total_common_files": 2,
                "checksum_mismatches": [],
                "checksum_matches": [
                    {
                        "path": "filepath1",
                        "path1_sha256": "filehash1",
                        "path2_sha256": "filehash1",
                        "filetype1": "ASCII text",
                        "filetype2": "ASCII text",
                    },
                    {
                        "path": "filepath2",
                        "path1_sha256": "filehash2",
                        "path2_sha256": "filehash2",
                        "filetype1": "ASCII text",
                        "filetype2": "ASCII text",
                    },
                ],
                "only_in_image1": [],
                "only_in_image2": [],
            },
        ),
        # Two paths, one match
        (
            {
                "folder_path1": "folder_path1",
                "hashed_files1": {
                    "filepath1": FileHash("filepath1", "ASCII text", "filehash1"),
                    "filepath2": FileHash("filepath2", "ASCII text", "filehash2"),
                },
                "folder_path2": "folder_path2",
                "hashed_files2": {
                    "filepath1": FileHash("filepath1", "ASCII text", "filehash1"),
                    "filepath2": FileHash("filepath2", "ASCII text", "filehash3"),
                },
            },
            {
                "image1": "folder_path1",
                "image2": "folder_path2",
                "total_common_files": 2,
                "checksum_mismatches": [
                    {
                        "path": "filepath2",
                        "path1_sha256": "filehash2",
                        "path2_sha256": "filehash3",
                        "filetype1": "ASCII text",
                        "filetype2": "ASCII text",
                    }
                ],
                "checksum_matches": [
                    {
                        "path": "filepath1",
                        "path1_sha256": "filehash1",
                        "path2_sha256": "filehash1",
                        "filetype1": "ASCII text",
                        "filetype2": "ASCII text",
                    }
                ],
                "only_in_image1": [],
                "only_in_image2": [],
            },
        ),
        # Three paths, two only in
        (
            {
                "folder_path1": "folder_path1",
                "hashed_files1": {
                    "filepath1": FileHash("filepath1", "ASCII text", "filehash1"),
                    "filepath2": FileHash("filepath2", "ASCII text", "filehash2"),
                },
                "folder_path2": "folder_path2",
                "hashed_files2": {
                    "filepath1": FileHash("filepath1", "ASCII text", "filehash1"),
                    "filepath3": FileHash("filepath3", "ASCII text", "filehash3"),
                },
            },
            {
                "image1": "folder_path1",
                "image2": "folder_path2",
                "total_common_files": 1,
                "checksum_mismatches": [],
                "checksum_matches": [
                    {
                        "path": "filepath1",
                        "path1_sha256": "filehash1",
                        "path2_sha256": "filehash1",
                        "filetype1": "ASCII text",
                        "filetype2": "ASCII text",
                    }
                ],
                "only_in_image1": ["filepath2"],
                "only_in_image2": ["filepath3"],
            },
        ),
    ],
)
def test_summarize_checksums(test_input, expected):
    """Test summarize_checkums."""
    output = summarize_checksums(**test_input)
    assert output == expected


@pytest.mark.parametrize(
    "test_input, expected",
    [
        # No mismatches, 1 match
        (
            {
                "checksum_summary": {
                    "image1": "source1/rootfs",
                    "image2": "source2/rootfs",
                    "total_common_files": 2,
                    "checksum_mismatches": [],
                    "checksum_matches": [
                        {
                            "path": "path1",
                            "path1_sha256": "hash1",
                            "path2_sha256": "hash1",
                            "filetype1": "ASCII text",
                            "filetype2": "ASCII text",
                        },
                    ],
                    "only_in_image1": [],
                    "only_in_image2": [],
                },
                "diff_lookup": {},
                "hashed_files1": {
                    "path1": FileHash("path1", "ASCII text", "hash1")
                },
                "hashed_files2": {
                    "path1": FileHash("path1", "ASCII text", "hash1")
                },
            },
            ([], []),
        ),
        # 2 nontrivial mismatch, 1 match
        (
            {
                "checksum_summary": {
                    "image1": "source1/rootfs",
                    "image2": "source2/rootfs",
                    "total_common_files": 2,
                    "checksum_mismatches": [
                        {
                            "path": "path1",
                            "path1_sha256": "hash1",
                            "path2_sha256": "hash1.1",
                            "filetype1": "ASCII text",
                            "filetype2": "ASCII text",
                        },
                        {
                            "path": "path2",
                            "path1_sha256": "hash2",
                            "path2_sha256": "hash2.1",
                            "filetype1": "ASCII text",
                            "filetype2": "ASCII text",
                        },
                    ],
                    "checksum_matches": [
                        {
                            "path": "path3",
                            "path1_sha_256": "hash3",
                            "path1_sha256": "hash3",
                            "filetype1": "ASCII text",
                            "filetype2": "ASCII text",
                        }
                    ],
                    "only_in_image1": [],
                    "only_in_image2": [],
                },
                "diff_lookup": {
                    ("path1", "path1"): [
                        {
                        "source1": "source1/rootfs/path1",
                        "source2": "source2/rootfs/path1",
                        "unified_diff_id": 1,
                        "unified_diff": "diff1",
                        },
                    ],
                    ("path2", "path2"): [
                        {
                            "source1": "source1/rootfs/path2",
                            "source2": "source2/rootfs/path2",
                            "unified_diff_id": 2,
                            "unified_diff": "diff2",
                        },
                    ],
                },
                "hashed_files1": {
                    "path1": FileHash("path1", "ASCII text", "hash1"),
                    "path2": FileHash("path2", "ASCII text", "hash2"),
                    "path3": FileHash("path3", "ASCII text", "hash3"),
                },
                "hashed_files2": {
                    "path1": FileHash("path1", "ASCII text", "hash1.1"),
                    "path2": FileHash("path2", "ASCII text", "hash2.1"),
                    "path3": FileHash("path3", "ASCII text", "hash3"),
                }
            },
            ([], []),
        ),
    ],
)
def test_classify_checksum_mismatches(test_input, expected):
    """Test classify_checksum_mismatches."""
    output = classify_checksum_mismatches(**test_input)

    print(output)

    assert output == expected


def test_hash_folder_contents(tmp_path):
    """Test hash_folder_contents."""
    # Create sample files
    file1 = tmp_path / "a.txt"
    file1.write_text("hello")

    subdir = tmp_path / "subdir"
    subdir.mkdir()
    file2 = subdir / "b.txt"
    file2.write_text("world")

    result = hash_folder_contents(tmp_path)

    # Assertions
    assert isinstance(result, dict)
    assert set(result.keys()) == {"a.txt", "subdir/b.txt"}
    for path, filehash in result.items():
        assert isinstance(filehash, FileHash)
        assert filehash.path == path
        assert re.fullmatch(r"[a-f0-9]{64}", filehash.hash)  # make sure it's valid SHA256
        assert isinstance(filehash.filetype, str)
        assert filehash.filetype != ""