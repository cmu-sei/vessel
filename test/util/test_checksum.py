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

import re

import pytest

from vessel.utils.checksum import (
    FileHash,
    classify_checksum_mismatches,
    hash_folder_contents,
    summarize_checksums,
)

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
        assert re.fullmatch(
            r"[a-f0-9]{64}", filehash.hash
        )  # make sure it's valid SHA256
        assert isinstance(filehash.filetype, str)
        assert filehash.filetype != ""

@pytest.mark.parametrize(
    "test_input, expected",
    [
        # Two files, two matches
        (
            {
                "diff_lookup": {},
                "folder_path1": "folder_path1",
                "hashed_files1": {
                    "filepath1": FileHash(
                        "filepath1", "ASCII text", "filehash1"
                    ),
                    "filepath2": FileHash(
                        "filepath2", "ASCII text", "filehash2"
                    ),
                },
                "folder_path2": "folder_path2",
                "hashed_files2": {
                    "filepath1": FileHash(
                        "filepath1", "ASCII text", "filehash1"
                    ),
                    "filepath2": FileHash(
                        "filepath2", "ASCII text", "filehash2"
                    ),
                },
            },
            {
                "image1": "folder_path1",
                "image2": "folder_path2",
                "total_common_files": 2,
                "checksum_mismatches": [],
                "checksum_matches": [
                    {
                        "path1": "filepath1",
                        "path2": "filepath1",
                        "path1_sha256": "filehash1",
                        "path2_sha256": "filehash1",
                        "filetype1": "ASCII text",
                        "filetype2": "ASCII text",
                    },
                    {
                        "path1": "filepath2",
                        "path2": "filepath2",
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
                "diff_lookup": {},
                "folder_path1": "folder_path1",
                "hashed_files1": {
                    "filepath1": FileHash(
                        "filepath1", "ASCII text", "filehash1"
                    ),
                    "filepath2": FileHash(
                        "filepath2", "ASCII text", "filehash2"
                    ),
                },
                "folder_path2": "folder_path2",
                "hashed_files2": {
                    "filepath1": FileHash(
                        "filepath1", "ASCII text", "filehash1"
                    ),
                    "filepath2": FileHash(
                        "filepath2", "ASCII text", "filehash3"
                    ),
                },
            },
            {
                "image1": "folder_path1",
                "image2": "folder_path2",
                "total_common_files": 2,
                "checksum_mismatches": [
                    {
                        "path1": "filepath2",
                        "path2": "filepath2",
                        "path1_sha256": "filehash2",
                        "path2_sha256": "filehash3",
                        "filetype1": "ASCII text",
                        "filetype2": "ASCII text",
                    }
                ],
                "checksum_matches": [
                    {
                        "path1": "filepath1",
                        "path2": "filepath1",
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
                "diff_lookup": {},
                "folder_path1": "folder_path1",
                "hashed_files1": {
                    "filepath1": FileHash(
                        "filepath1", "ASCII text", "filehash1"
                    ),
                    "filepath2": FileHash(
                        "filepath2", "ASCII text", "filehash2"
                    ),
                },
                "folder_path2": "folder_path2",
                "hashed_files2": {
                    "filepath1": FileHash(
                        "filepath1", "ASCII text", "filehash1"
                    ),
                    "filepath3": FileHash(
                        "filepath3", "ASCII text", "filehash3"
                    ),
                },
            },
            {
                "image1": "folder_path1",
                "image2": "folder_path2",
                "total_common_files": 1,
                "checksum_mismatches": [],
                "checksum_matches": [
                    {
                        "path1": "filepath1",
                        "path2": "filepath1",
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
        # No mismatches, empty trivial and nontrivial
        (
            {
                "checksum_summary": {
                    "image1": "source1/rootfs",
                    "image2": "source2/rootfs",
                    "total_common_files": 2,
                    "checksum_mismatches": [],
                    "checksum_matches": [
                        {
                            "path1": "path1",
                            "path2": "path1",
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
        # Only flagged failures, all Low, all metadata -> nontrivial
        (
            {
                "checksum_summary": {
                    "image1": "source1/rootfs",
                    "image2": "source2/rootfs",
                    "total_common_files": 1,
                    "checksum_mismatches": [
                        {
                            "path1": "path1",
                            "path2": "path1",
                            "filetype1": "ASCII text",
                            "filetype2": "ASCII text",
                        }
                    ],
                    "checksum_matches": [],
                    "only_in_image1": [],
                    "only_in_image2": [],
                },
                "diff_lookup": {
                    ("path1", "path1"): [
                        {
                            "flagged_failures": [
                                {
                                    "id": "TIME007",
                                    "description": "File listing time difference in different format.",
                                    "metadata": True,
                                    "severity": "Low",
                                }
                            ]
                        }
                    ]
                },
                "hashed_files1": {
                    "path1": FileHash("path1", "ASCII text", "h1")
                },
                "hashed_files2": {
                    "path1": FileHash("path1", "ASCII text", "h2")
                },
            },
            (
                [],  # Empty trivial
                [
                    {
                        "files1": "path1",
                        "files2": "path1",
                        "flagged_failure_types": [
                            "TIME007|File listing time difference in different format."
                        ],
                        "filetype1": "ASCII text",
                        "filetype2": "ASCII text",
                    }
                ],
            ),
        ),
        # Only flagged failures, all Low, at least one metadata is False -> trivial
        (
            {
                "checksum_summary": {
                    "image1": "source1/rootfs",
                    "image2": "source2/rootfs",
                    "total_common_files": 1,
                    "checksum_mismatches": [
                        {
                            "path1": "path1",
                            "path2": "path1",
                            "filetype1": "ASCII text",
                            "filetype2": "ASCII text",
                        }
                    ],
                    "checksum_matches": [],
                    "only_in_image1": [],
                    "only_in_image2": [],
                },
                "diff_lookup": {
                    ("path1", "path1"): [
                        {
                            "flagged_failures": [
                                {
                                    "id": "TIME007",
                                    "description": "File listing time difference in different format.",
                                    "metadata": True,
                                    "severity": "Low",
                                },
                                {
                                    "id": "TIME008",
                                    "description": "Logging time difference.",
                                    "metadata": False,
                                    "severity": "Low",
                                },
                            ]
                        }
                    ]
                },
                "hashed_files1": {
                    "path1": FileHash("path1", "ASCII text", "h1")
                },
                "hashed_files2": {
                    "path1": FileHash("path1", "ASCII text", "h2")
                },
            },
            (
                [
                    {
                        "files1": "path1",
                        "files2": "path1",
                        "flagged_failure_types": [
                            "TIME007|File listing time difference in different format.",
                            "TIME008|Logging time difference.",
                        ],
                        "filetype1": "ASCII text",
                        "filetype2": "ASCII text",
                    }
                ],
                [],  # Empty nontrivial
            ),
        ),
        # Only flagged failures, but one is not Low severity(nontrivial) -> nontrivial
        (
            {
                "checksum_summary": {
                    "image1": "source1/rootfs",
                    "image2": "source2/rootfs",
                    "total_common_files": 1,
                    "checksum_mismatches": [
                        {
                            "path1": "path1",
                            "path2": "path1",
                            "filetype1": "ASCII text",
                            "filetype2": "ASCII text",
                        }
                    ],
                    "checksum_matches": [],
                    "only_in_image1": [],
                    "only_in_image2": [],
                },
                "diff_lookup": {
                    ("path1", "path1"): [
                        {
                            "flagged_failures": [
                                {
                                    "id": "RAND006",
                                    "description": "Generated certificate differences",
                                    "metadata": False,
                                    "severity": "Medium",
                                }
                            ]
                        }
                    ]
                },
                "hashed_files1": {
                    "path1": FileHash("path1", "ASCII text", "h1")
                },
                "hashed_files2": {
                    "path1": FileHash("path1", "ASCII text", "h2")
                },
            },
            (
                [],  # Empty trivial
                [
                    {
                        "files1": "path1",
                        "files2": "path1",
                        "flagged_failure_types": [
                            "RAND006|Generated certificate differences"
                        ],
                        "filetype1": "ASCII text",
                        "filetype2": "ASCII text",
                    }
                ],
            ),
        ),
        # Unknown failures -> nontrivial
        (
            {
                "checksum_summary": {
                    "image1": "source1/rootfs",
                    "image2": "source2/rootfs",
                    "total_common_files": 1,
                    "checksum_mismatches": [
                        {
                            "path1": "path1",
                            "path2": "path1",
                            "filetype1": "ASCII text",
                            "filetype2": "ASCII text",
                        }
                    ],
                    "checksum_matches": [],
                    "only_in_image1": [],
                    "only_in_image2": [],
                },
                "diff_lookup": {
                    ("unknownfile", "unknownfile"): [
                        {
                            "unknown_failures": [
                                {
                                    "minus_file_line_number": 2,
                                    "plus_file_line_number": 2,
                                    "minus_unmatched_str": "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDEg+yzqceNP49w",
                                    "plus_unmatched_str": "MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCzAlorKb6UtjG4",
                                }
                            ]
                        }
                    ]
                },
                "hashed_files1": {
                    "path1": FileHash("path1", "ASCII text", "h1")
                },
                "hashed_files2": {
                    "path1": FileHash("path1", "ASCII text", "h2")
                },
            },
            (
                [],  # Empty trivial
                [
                    {
                        "files1": "path1",
                        "files2": "path1",
                        "flagged_failure_types": [],
                        "filetype1": "ASCII text",
                        "filetype2": "ASCII text",
                    }
                ],
            ),
        ),
        # No flagged failures nor unknown failures -> nontrivial
        (
            {
                "checksum_summary": {
                    "image1": "source1/rootfs",
                    "image2": "source2/rootfs",
                    "total_common_files": 1,
                    "checksum_mismatches": [
                        {
                            "path1": "path1",
                            "path2": "path1",
                            "filetype1": "ASCII text",
                            "filetype2": "ASCII text",
                        }
                    ],
                    "checksum_matches": [],
                    "only_in_image1": [],
                    "only_in_image2": [],
                },
                "diff_lookup": {
                    ("path1", "path1"): [
                        {
                            # No flagged failures nor unknown failures
                        }
                    ]
                },
                "hashed_files1": {
                    "path1": FileHash("path1", "ASCII text", "h1")
                },
                "hashed_files2": {
                    "path1": FileHash("path1", "ASCII text", "h2")
                },
            },
            (
                [],  # Empty trivial
                [
                    {
                        "files1": "path1",
                        "files2": "path1",
                        "flagged_failure_types": [],
                        "filetype1": "ASCII text",
                        "filetype2": "ASCII text",
                    }
                ],
            ),
        ),
    ],
)
def test_classify_checksum_mismatches(test_input, expected):
    """Test classify_checksum_mismatches."""
    output = classify_checksum_mismatches(**test_input)
    assert output == expected
