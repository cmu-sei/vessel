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

from vessel.utils.checksum import FileHash, summarize_checksums


@pytest.mark.parametrize(
    "test_input, expected",
    [
        # Two files, two matches
        (
            {
                "folder_path1": "folder_path1",
                "hashed_files1": [
                    FileHash("filepath1", "ASCII text", "filehash1"),
                    FileHash("filepath2", "ASCII text", "filehash2"),
                ],
                "folder_path2": "folder_path2",
                "hashed_files2": [
                    FileHash("filepath1", "ASCII text", "filehash1"),
                    FileHash("filepath2", "ASCII text", "filehash2"),
                ],
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
                "hashed_files1": [
                    FileHash("filepath1", "ASCII text", "filehash1"),
                    FileHash("filepath2", "ASCII text", "filehash2"),
                ],
                "folder_path2": "folder_path2",
                "hashed_files2": [
                    FileHash("filepath1", "ASCII text", "filehash1"),
                    FileHash("filepath2", "ASCII text", "filehash3"),
                ],
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
                "hashed_files1": [
                    FileHash("filepath1", "ASCII text", "filehash1"),
                    FileHash("filepath2", "ASCII text", "filehash2"),
                ],
                "folder_path2": "folder_path2",
                "hashed_files2": [
                    FileHash("filepath1", "ASCII text", "filehash1"),
                    FileHash("filepath3", "ASCII text", "filehash3"),
                ],
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
