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

from vessel.diff.diff_command import DiffCommand
from vessel.utils.checksum import FileHash


def test_write_to_files_and_unified_diffs(tmp_path):
    """Verify that write_to_files creates summary, unified diffs, and checksum summary properly"""
    diff_command = DiffCommand([], "file", str(tmp_path), str(tmp_path))

    diffs = [
        {"unified_diff": "diff1", "meta": 123},
        {"unified_diff": "diff2", "meta": 456},
    ]

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

    # Pass explicit counts into write_to_files so we can assert the JSON output has the same count
    # Set unknown to 1, trivial to 2, and nontrivial to 3
    diff_command.write_to_files(
        1, 2, 3, diffs, files_summary, checksum_summary
    )

    summary_file = tmp_path / diff_command.summary_output_file_name
    unified_file = tmp_path / diff_command.unified_diff_output_file_name

    summary_json = json.loads(summary_file.read_text())
    unified_json = json.loads(unified_file.read_text())

    failure_summary = summary_json["summary"]["failure_summary"]
    assert failure_summary["unknown_failures"] == 1
    assert failure_summary["trivial_failures"] == 2
    assert failure_summary["nontrivial_failures"] == 3
    assert failure_summary["flagged_failures"] == 5  # trivial + nontrivial
    assert (
        failure_summary["total_failures"] == 6
    )  # unknown + trivial + nontrivial

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


@patch("vessel.diff.diff_command.hash_folder_contents")
@patch("vessel.diff.diff_command.save_checksum_metadata")
@patch("vessel.diff.diff_command.generate_filesummary_and_checksum")
def test_process_and_save_results_invokes_dependencies(
    mock_generate, mock_save, mock_hash, tmp_path
):
    """
    Verify process_and_save_results hashes, saves metadata, and writes output files
    Flow tested: hashing -> save metadata -> generate summaries -> write
    """
    hashed_files_image1 = {"file1": object()}
    hashed_files_image2 = {"file2": object()}
    mock_hash.side_effect = [hashed_files_image1, hashed_files_image2]

    files_summary = ["files_summary"]
    checksum_summary = {"checksum_summary": 1}
    mock_generate.return_value = (files_summary, checksum_summary)

    diff_command = DiffCommand([], "file", str(tmp_path), str(tmp_path))
    diff_command.write_to_files = MagicMock()

    diff_command.process_and_save_results(
        rootfs_path1=tmp_path,
        rootfs_path2=tmp_path,
        diff_list=["dummy_diff"],
        unknown=1,
        trivial=2,
        nontrivial=3,
    )

    # Assert hash_folder_contents should be used for both images
    assert mock_hash.call_count == 2

    # Assert save_checksum_metadata should receive the exact hashed dicts
    save_args, save_kwargs = mock_save.call_args
    assert save_args[1] is hashed_files_image1
    assert save_args[2] is hashed_files_image2
    assert save_kwargs["image1_path"] == str(tmp_path)
    assert save_kwargs["image2_path"] == str(tmp_path)

    # Assert generate_filesummary_and_checksum should receive the same hashed dicts,
    # and the first positional arg should be the passed diff_list
    gen_args, gen_kwargs = mock_generate.call_args
    assert gen_args[0] == ["dummy_diff"]
    assert gen_kwargs["hashed_files1"] is hashed_files_image1
    assert gen_kwargs["hashed_files2"] is hashed_files_image2
    assert gen_kwargs["image1_path"] == str(tmp_path)
    assert gen_kwargs["image2_path"] == str(tmp_path)

    # Assert write_to_files called with the counts we passed and generated summaries
    diff_command.write_to_files.assert_called_once_with(
        1, 2, 3, ["dummy_diff"], files_summary, checksum_summary
    )


def test_compare_diffoscope_and_checksum_json_success(tmp_path):
    """
    Verify compare_diffoscope_and_checksum_json passes lookups and writes the expected results
    Flow tested: Load checksum metadata -> Build filetype lookups -> Parse → Generate summaries -> Write
    """
    diffoscope_path = tmp_path / "diff.json"
    checksum_path = tmp_path / "checksum_metadata.json"

    diffoscope_json_content = {"diff": "data"}
    diffoscope_path.write_text(json.dumps(diffoscope_json_content))
    checksum_path.write_text(json.dumps({}))

    diff_command = DiffCommand(
        input_files=[str(diffoscope_path), str(checksum_path)],
        compare_level="file",
        data_dir=str(tmp_path),
        output_dir=str(tmp_path),
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
        patch(
            "vessel.diff.diff_command.parse_diffoscope_output"
        ) as mock_parse,
        patch(
            "vessel.diff.diff_command.generate_filesummary_and_checksum"
        ) as mock_generate,
        patch.object(diff_command, "write_to_files") as mock_write,
    ):
        mock_load.return_value = (
            hashed_files1,
            hashed_files2,
            "img1_path",
            "img2_path",
        )
        mock_parse.return_value = (1, 2, 3, ["dummy_diffs"])
        mock_generate.return_value = (
            ["files_summary"],
            {"checksum_summary": 1},
        )

        result = diff_command.compare_diffoscope_and_checksum_json()
        assert result is True

        # Assert load was called on the checksum path
        mock_load.assert_called_once_with(str(checksum_path))

        # Assert parse received the diffoscope JSON, current flags, and the lookups built from hashed maps
        parse_args, parse_kwargs = mock_parse.call_args
        assert parse_args[0] == diffoscope_json_content
        assert parse_args[1] == diff_command.flags
        assert parse_kwargs["filetype_lookup1"] == {"a.txt": "ASCII text"}
        assert parse_kwargs["filetype_lookup2"] == {
            "b.bin": "application/octet-stream"
        }

        # Assert generate_filesummary_and_checksum received the hashed maps and image path
        gen_args, gen_kwargs = mock_generate.call_args
        assert gen_args[0] == ["dummy_diffs"]
        assert gen_kwargs["hashed_files1"] == hashed_files1
        assert gen_kwargs["hashed_files2"] == hashed_files2
        assert gen_kwargs["image1_path"] == "img1_path"
        assert gen_kwargs["image2_path"] == "img2_path"

        # Assert write_to_files received the exact outputs from parse and generate
        write_args, write_kwargs = mock_write.call_args
        assert write_args == (
            1,  # unknown
            2,  # trivial
            3,  # nontrivial
            ["dummy_diffs"],  # diff_list
            ["files_summary"],  # files_summary
            {"checksum_summary": 1},  # checksum_summary
        )
        assert write_kwargs == {}


def test_compare_diffoscope_and_checksum_json_rejects_bad_pair(
    tmp_path, caplog
):
    """Return False if two JSONs are provided but none is named checksum_metadata.json"""
    diffoscope_path = tmp_path / "first.json"
    another_json_path = tmp_path / "second.json"

    diffoscope_path.write_text(json.dumps({"diff": "data"}))
    another_json_path.write_text(json.dumps({"other": "data"}))

    diff_command = DiffCommand(
        input_files=[str(diffoscope_path), str(another_json_path)],
        compare_level="file",
        data_dir=str(tmp_path),
        output_dir=str(tmp_path),
    )

    result = diff_command.compare_diffoscope_and_checksum_json()
    assert result is False
    # Make sure the error message is correct
    assert any(
        rec.getMessage()
        == "When providing two JSON files, one must be a checksum_metadata.json file."
        for rec in caplog.records
    )
