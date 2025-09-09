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

from pathlib import Path

import pytest

from vessel.diff.helpers import metadata_diff
from vessel.diff.helpers.metadata_diff import MetadataDiff, MetadataFlag
from vessel.utils import skopeo
from vessel.utils.uri import ImageURI


def test_compare_metadata(tmp_path: Path):
    """Tests that for two known images, the two known diffs are found."""
    test_image_name = "hello-world:latest"
    test_image_uri = ImageURI(f"docker://{test_image_name}")
    output_path1 = skopeo.skopeo_copy(test_image_uri, str(tmp_path))

    test_image_name = "busybox:1.36.1"
    test_image_uri = ImageURI(f"docker://{test_image_name}")
    output_path2 = skopeo.skopeo_copy(test_image_uri, str(tmp_path))

    diffs = metadata_diff.compare_metadata(
        Path(output_path1), Path(output_path2)
    )
    print(f"Diffs: {diffs}")
    assert len(diffs) == 5


def test_match_flags():
    """Checks that flag matching works."""
    diffs = [
        MetadataDiff("a", 1, None),
        MetadataDiff("a", 1, 2),
        MetadataDiff("b", 1, 2),
        MetadataDiff("c", 1, 2),
    ]
    flags = [MetadataFlag("C1", "a", "Low"), MetadataFlag("C2", "b", "High")]

    updated_diffs, summary = metadata_diff.match_flags(diffs, flags)

    for diff in updated_diffs:
        if diff.key == "a":
            assert diff.matched_flag == MetadataFlag("C1", "a", "Low")
        elif diff.key == "b":
            assert diff.matched_flag == MetadataFlag("C2", "b", "High")
        else:
            assert not diff.matched_flag

    assert summary.total_failures == 4
    assert summary.flagged_failures == 3
    assert summary.trivial_failures == 2
    assert summary.nontrivial_failures == 1


@pytest.mark.parametrize(
    "d1, d2, key, expected_output",
    [
        ({"a": 1}, {"b": 2}, "a", MetadataDiff("a", 1, None)),
        ({"a": 1}, {"b": 2}, "b", MetadataDiff("b", None, 2)),
        ({"a": 1}, {"a": 2}, "a", MetadataDiff("a", 1, 2)),
        ({"a": 1}, {"a": 1}, "a", None),
        ({"a": 1}, {"a": 2}, "c", None),
    ],
)
def test_compare_key(d1, d2, key, expected_output):
    """Compares a key in two dicts."""
    output = metadata_diff._compare_key(d1, d2, key)
    assert output == expected_output


@pytest.mark.parametrize(
    "d1, d2, key, parent, expected_output",
    [
        (
            {"p": {"a": 1}},
            {"p": {"a": 2}},
            "a",
            "p",
            MetadataDiff("p/a", 1, 2),
        ),
        (
            {"a": 1},
            {"b": 2},
            "a",
            None,
            MetadataDiff("a", 1, None),
        ),
    ],
)
def test_compare_full_key(d1, d2, key, parent, expected_output):
    """Compares a key with potential parent in two dicts."""
    output = metadata_diff._compare_full_key(d1, d2, key, parent)
    assert output == expected_output


@pytest.mark.parametrize(
    "d1, d2, key, parent",
    [
        ({"p": 1}, {"p": {"a": 2}}, "a", "p"),
    ],
)
def test_compare_full_key_not_nested(d1, d2, key, parent):
    """Compares a key with potential parent in two dicts."""
    with pytest.raises(RuntimeError):
        _ = metadata_diff._compare_full_key(d1, d2, key, parent)


@pytest.mark.parametrize(
    "d1, d2, expected_output",
    [
        (
            {"a": 1, "b": 3},
            {"b": 2, "c": 4},
            [
                MetadataDiff("a", 1, None),
                MetadataDiff("b", 3, 2),
                MetadataDiff("c", None, 4),
            ],
        ),
        (
            {"a": 1, "b": 3},
            {"b": 2},
            [MetadataDiff("a", 1, None), MetadataDiff("b", 3, 2)],
        ),
        (
            {"a": {"a1": 1}},
            {"a": {"a2": 1}},
            [MetadataDiff("a/a1", 1, None), MetadataDiff("a/a2", None, 1)],
        ),
    ],
)
def test_compare_dicts(d1, d2, expected_output):
    """Compares two dicts."""
    output = metadata_diff._compare_dicts(d1, d2)
    assert output == expected_output
