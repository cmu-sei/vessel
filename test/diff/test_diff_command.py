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
# DM24-1321# tests/test_diff_command.py

"""Unit tests for diff_command"""

import json
from unittest.mock import MagicMock, patch

import pytest

from test.fixture import make_test_file_diff
from vessel.diff.diff_command import DiffCommand
from vessel.diff.helpers.failure import FailureSummary
from vessel.diff.helpers.file_diff import FileDiffs
from vessel.diff.helpers.metadata_diff import (
    MetadataDiff,
    MetadataDiffs,
)
from vessel.utils.checksum import FileHash


def test_write_to_files_and_unified_diffs(tmp_path):
    """Verify that write_to_files creates summary, unified diffs, checksum summary, and metadata summary properly"""
    diff_command = DiffCommand(
        [], "file", str(tmp_path), str(tmp_path), profile_enabled=False
    )

    diffs = FileDiffs([make_test_file_diff(), make_test_file_diff()])

    files_summary = [
        {
            "trivial_checksum_different_files": ["fileA"],
            "nontrivial_checksum_different_files": ["fileB"],
        }
    ]

    checksum_summary = {
        "total_common_files": 1,
        "checksum_matches": ["hello"],
        "only_in_image1": ["first_file", "second_file"],
        "only_in_image2": ["third_file", "fourth_file"],
    }

    meta_diffs = MetadataDiffs(
        [
            MetadataDiff(
                "created", "2023-01-01T00:00:00Z", "2023-01-02T00:00:00Z"
            ),
            MetadataDiff(
                "config/Env", {"hello": "world1"}, {"hello": "world2"}
            ),
        ]
    )
    meta_summary = FailureSummary(0, 1, 1)

    diff_command._write_to_files(
        FailureSummary(1, 2, 3),
        FailureSummary(1, 2, 3),
        meta_summary,
        diffs,
        meta_diffs,
        files_summary,
        checksum_summary,
    )

    summary_file = tmp_path / diff_command.SUMMARY_OUTPUT_FILENAME
    unified_file = tmp_path / diff_command.UNIFIED_DIFF_OUTPUT_FILENAME
    meta_file = tmp_path / diff_command.METADATA_DIFF_OUTPUT_FILENAME

    summary_json = json.loads(summary_file.read_text())
    unified_json = json.loads(unified_file.read_text())
    meta_json = json.loads(meta_file.read_text())

    failure_summary = summary_json["summary"]["total_failure_summary"]
    assert failure_summary["unknown_failures"] == 1
    assert failure_summary["trivial_failures"] == 2
    assert failure_summary["nontrivial_failures"] == 3

    assert len(summary_json["diffs"]) == 2
    assert "1" in unified_json and "2" in unified_json

    checksum_section = summary_json["summary"]["checksum summary"]
    assert checksum_section["total_common_files"] == 1
    assert (
        checksum_section["total_image1_file_count"] == 3
    )  # 1 common + 2 unique
    assert (
        checksum_section["total_image2_file_count"] == 3
    )  # 1 common + 2 unique
    assert checksum_section["identical_file_count"] == 1
    assert checksum_section["only_in_image1_file_count"] == 2
    assert checksum_section["only_in_image2_file_count"] == 2
    assert checksum_section["trivial_checksum_different_file_count"] == 1
    assert checksum_section["nontrivial_checksum_different_file_count"] == 1

    assert isinstance(meta_json, list)
    assert {
        "key": "created",
        "value1": "2023-01-01T00:00:00Z",
        "value2": "2023-01-02T00:00:00Z",
        "matched_flag": None,
    } in meta_json
    assert {
        "key": "config/Env",
        "value1": {"hello": "world1"},
        "value2": {"hello": "world2"},
        "matched_flag": None,
    } in meta_json

    meta_section = summary_json["summary"]["meta_failure_summary"]
    assert meta_section["unknown_failures"] == 0
    assert meta_section["trivial_failures"] == 1
    assert meta_section["nontrivial_failures"] == 1
    assert meta_section["flagged_failures"] == 2
    assert meta_section["total_failures"] == 2


@patch("vessel.diff.diff_command.DiffoscopeParser")
@patch("vessel.diff.diff_command.generate_filesummary_and_checksum")
def test_process_and_save_results_invokes_dependencies(
    mock_generate, mock_parser, tmp_path
):
    """
    Verify process_and_save_results parses diffoscope, generates summaries, and writes output files
    Flow tested: parse -> generate summaries -> write
    """
    files_summary = ["files_summary"]
    checksum_summary = {"checksum_summary": 1}
    mock_generate.return_value = (files_summary, checksum_summary)

    mocked_file_diffs = FileDiffs([make_test_file_diff()])
    mock_parser.return_value.failure_summary = FailureSummary(1, 2, 3)
    mock_parser.return_value.diff_list = mocked_file_diffs

    diff_command = DiffCommand(
        [], str(tmp_path), "file", str(tmp_path), profile_enabled=False
    )
    diff_command._write_to_files = MagicMock()

    diffoscope_output = tmp_path.joinpath("diff.json")
    diffoscope_output.write_text("{}")

    diff_command._process_and_write_results(
        image1_path=tmp_path,
        image2_path=tmp_path,
        diffoscope_output_path=diffoscope_output,
        meta_diffs=MetadataDiffs(),
        hashed_files1={"a": "x"},
        hashed_files2={"b": "y"},
    )

    mock_parser.assert_called_once()
    mock_generate.assert_called_once()

    diff_command._write_to_files.assert_called_once()
    _, kwargs = diff_command._write_to_files.call_args
    assert kwargs["file_failure_summary"].unknown_failure_count == 1
    assert kwargs["file_failure_summary"].trivial_failure_count == 2
    assert kwargs["file_failure_summary"].nontrivial_failure_count == 3
    assert isinstance(kwargs["file_diffs"], FileDiffs)
    assert kwargs["file_diffs"].diffs
    assert "total_failure_summary" in kwargs
    assert "file_failure_summary" in kwargs
    assert "meta_failure_summary" in kwargs
    assert kwargs["files_summary"] == ["files_summary"]
    assert kwargs["checksum_summary"] == {"checksum_summary": 1}


def test_compare_diffoscope_and_checksum_json_success(tmp_path):
    """
    Verify compare_diffoscope_and_checksum_json passes lookups and writes the expected results
    Flow tested: Load checksum metadata -> Build filetype lookups -> Parse → Generate summaries -> Write
    """
    diffoscope_path = tmp_path / "diffoscope_output.json"
    checksum_path = tmp_path / "checksum_metadata.json"
    meta_diffs_path = tmp_path / "meta_diffs.json"

    diffoscope_path.write_text("{}")
    checksum_path.write_text("{}")
    meta_diffs_path.write_text(
        json.dumps(
            [
                {
                    "key": "created",
                    "value1": "2023-01-01T00:00:00Z",
                    "value2": "2023-01-02T00:00:00Z",
                },
                {
                    "key": "config/Env",
                    "value1": {"hello": "world1"},
                    "value2": {"hello": "world2"},
                },
            ]
        )
    )

    diff_command = DiffCommand(
        input_files=[
            str(diffoscope_path),
            str(checksum_path),
            str(meta_diffs_path),
        ],
        data_dir=str(tmp_path),
        mode="json",
        output_dir=str(tmp_path),
        profile_enabled=False,
    )

    # Build hashed maps to generate filetype lookup dicts
    hashed_files1 = {
        "a.txt": FileHash(path="a.txt", filetype="ASCII text", hash="hashA")
    }
    hashed_files2 = {
        "b.bin": FileHash(
            path="b.bin", filetype="application/octet-stream", hash="hashB"
        )
    }

    with (
        patch("vessel.diff.diff_command.load_checksum_metadata") as mock_load,
        patch("vessel.diff.diff_command.DiffoscopeParser") as mock_parser,
        patch(
            "vessel.diff.diff_command.generate_filesummary_and_checksum"
        ) as mock_generate,
        patch(
            "vessel.diff.diff_command.metadata_diff.match_flags"
        ) as mock_match,
        patch.object(diff_command, "_write_to_files") as mock_write,
    ):
        mock_load.return_value = (
            hashed_files1,
            hashed_files2,
            "img1_path",
            "img2_path",
        )

        mocked_file_diffs = FileDiffs([make_test_file_diff()])
        mock_parser.return_value.failure_summary = FailureSummary(1, 2, 3)
        mock_parser.return_value.diff_list = mocked_file_diffs

        mock_generate.return_value = (
            ["files_summary"],
            {"checksum_summary": 1},
        )

        meta_diffs = MetadataDiffs(
            [
                MetadataDiff(
                    "created", "2023-01-01T00:00:00Z", "2023-01-02T00:00:00Z"
                ),
                MetadataDiff(
                    "config/Env", {"hello": "world1"}, {"hello": "world2"}
                ),
            ]
        )
        meta_summary = FailureSummary(0, 1, 1)
        mock_match.return_value = (meta_diffs, meta_summary)

        result = diff_command._compare_json_diff_outputs()
        assert result is True

        # Assert load was called on the checksum path
        mock_load.assert_called_once_with(str(checksum_path))
        parser_args, parser_kwargs = mock_parser.call_args
        assert parser_args[0] == {}  # diffoscope JSON
        assert parser_args[1] == diff_command.flags
        assert parser_args[2] == {"a.txt": "ASCII text"}  # filetype_lookup1
        assert parser_args[3] == {
            "b.bin": "application/octet-stream"
        }  # filetype_lookup2

        # _write_to_files should get FailureSummary objects and diffs
        mock_write.assert_called_once()
        _, kwargs = mock_write.call_args
        assert kwargs["file_failure_summary"].unknown_failure_count == 1
        assert kwargs["file_failure_summary"].trivial_failure_count == 2
        assert kwargs["file_failure_summary"].nontrivial_failure_count == 3
        assert isinstance(kwargs["file_diffs"], FileDiffs)
        assert kwargs["file_diffs"].diffs
        assert kwargs["files_summary"] == ["files_summary"]
        assert kwargs["checksum_summary"] == {"checksum_summary": 1}
        assert kwargs["meta_failure_summary"].trivial_failure_count == 1
        assert kwargs["meta_failure_summary"].nontrivial_failure_count == 1

        metadata_diffs_arg = kwargs["meta_diffs"]
        keys = [d.key for d in metadata_diffs_arg.diffs]
        assert "created" in keys
        assert "config/Env" in keys


def test_compare_diffoscope_and_checksum_json_rejects_bad_pair(
    tmp_path, caplog
):
    """Return False if JSON files are provided but not the required three"""
    diffoscope_path = tmp_path / "first.json"
    another_json_path = tmp_path / "second.json"

    diffoscope_path.write_text(json.dumps({"diff": "data"}))
    another_json_path.write_text(json.dumps({"other": "data"}))

    diff_command = DiffCommand(
        input_files=[str(diffoscope_path), str(another_json_path)],
        data_dir=str(tmp_path),
        mode="json",
        output_dir=str(tmp_path),
        profile_enabled=False,
    )

    with pytest.raises(RuntimeError) as excinfo:
        diff_command._compare_json_diff_outputs()

    # Make sure the error mentions that three JSON files are required
    assert "Three JSON files are needed" in str(excinfo.value)
