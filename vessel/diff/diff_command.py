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

"""Contain the main functionality for diff."""

import json
import subprocess
import tempfile
from logging import getLogger
from pathlib import Path
from typing import Any

import yaml

from vessel.diff.helpers import metadata_diff
from vessel.diff.helpers.checksum import (
    FileHash,
    generate_filesummary_and_checksum,
    hash_folder_contents,
    load_checksum_metadata,
    save_checksum_metadata,
)
from vessel.diff.helpers.diffoscope import (
    build_diffoscope_command,
    parse_diffoscope_output,
)
from vessel.diff.helpers.flag import Flag
from vessel.utils.oci import get_manifest_digest
from vessel.utils.skopeo import skopeo_copy
from vessel.utils.umoci import umoci_unpack
from vessel.utils.uri import ImageURI

logger = getLogger(__name__)


class DiffCommand:
    """Class that setups up and executes a diff operation."""

    CHECKSUM_METADATA_FILENAME = "checksum_metadata.json"

    def __init__(
        self: "DiffCommand",
        input_files: list[str],
        compare_level: str,
        data_dir: str,
        output_dir: str,
    ) -> None:
        """Initializer for a diff operation.

        Processes command-line arguments.
        """
        self.flags: list[Flag] = []
        self.input_files: list[str] = input_files
        self.compare_level: str = compare_level
        self.data_dir: str = data_dir
        self.output_dir: str = output_dir
        self.temp_dir: tempfile.TemporaryDirectory[str] | None = None
        self.image_uris: list[ImageURI] = []
        self.oci_image_paths: list[str] = []
        self.oci_runtime_paths: list[str] = []
        self.diffoscope_output_file_name = "diffoscope_output.json"
        self.summary_output_file_name = "summary.json"
        self.unified_diff_output_file_name = "unified_diffs.json"

    def execute(self: "DiffCommand") -> bool:
        """Executes a diff operation.

        Returns:
            True on success, else False
        """
        if not self._setup():
            return False

        if len(self.input_files) == 0:
            logger.error(
                "No inputs provided. Acceptable values are 2 image paths, or 2 JSON files (diffoscope output and checksum metadata)"
            )
            return False

        if len(self.input_files) > 2:
            logger.error(
                "Too many inputs provided. Acceptable values are 2 image paths, or 2 JSON files (diffoscope output and checksum metadata)."
            )
            return False

        # If two inputs are json files, perform json comparison
        if len(self.input_files) == 2 and all(
            f.endswith(".json") for f in self.input_files
        ):
            return self._compare_diffoscope_and_checksum_json()

        # Proceed with image comparison
        logger.info("Images to be compared:")
        logger.info("- %s", self.input_files[0])
        logger.info("- %s", self.input_files[1])

        if not self._convert_to_oci_folder():
            return False

        if self.compare_level == "image":
            return self._compare_images()

        if get_manifest_digest(
            self.oci_image_paths[0],
        ) == get_manifest_digest(self.oci_image_paths[1]):
            logger.info("All layers are identical")
            self._write_to_files(0, 0, 0, [], [], [], {})
            return True

        if self.compare_level == "file":
            return self._compare_files()

        logger.error("Invalid compare level selected.")
        return False

    def _setup(self: "DiffCommand") -> bool:
        """Sets up a diff operation.

        - If necessary, creates a temporary directory for intermediate results.
        - Reads in the flags

        Returns:
            True on success, else False
        """
        if self.data_dir:
            Path(self.data_dir).mkdir(parents=True, exist_ok=True)
        else:
            self.temp_dir = tempfile.TemporaryDirectory()
            self.data_dir = self.temp_dir.name

        if self.output_dir:
            Path(self.output_dir).mkdir(parents=True, exist_ok=True)
        else:
            self.output_dir = str(Path.cwd())

        with Path.open(
            Path(Path(__file__).resolve()).parent
            / "../config/diff_config.yaml",
        ) as config_file:
            try:
                config = yaml.safe_load(config_file)
                for flag in config["flags"]:
                    try:
                        temp_flag = Flag(
                            flag["id"],
                            flag["description"],
                            flag["severity"],
                            flag["metadata"],
                            flag["filepath"],
                            flag["filetype"],
                            flag["command"],
                            flag["comment"],
                            flag["indiff"],
                        )
                    except ValueError as e:
                        logger.exception("Error with flag: %s", e)
                        return False
                    self.flags.append(temp_flag)
            except yaml.YAMLError:
                logger.exception("Error reading the yaml config file.")
                return False

        return True

    def _convert_to_oci_folder(self: "DiffCommand") -> bool:
        """Converts images to a OCI data folder with skopeo."""
        self.image_uris = [
            ImageURI(container_transport)
            for container_transport in self.input_files
        ]

        if (self.image_uris[0].output_identifier == self.image_uris[1].output_identifier):  # noqa: E501 # fmt: skip
            self.image_uris[0].output_identifier = f"{self.image_uris[0].output_identifier}_0"  # noqa: E501 # fmt: skip
            self.image_uris[1].output_identifier = f"{self.image_uris[1].output_identifier}_1"  # noqa: E501 # fmt: skip

        self.oci_image_paths = [
            skopeo_copy(image_path, self.data_dir)
            for image_path in self.image_uris
        ]

        return True

    def _compare_images(self: "DiffCommand") -> bool:
        """Compares two images directly.

        Returns:
            True on success, else False
        """
        return self._compare(
            self.oci_image_paths[0], self.oci_image_paths[1], "_compare_images"
        )

    def _compare_files(self: "DiffCommand") -> bool:
        """Compare final image filesystem.

        Compares file-by-file after unpacking image into the final
        image filesystem.

        Returns:
            True on success, else False
        """
        self.oci_runtime_paths = umoci_unpack(
            self.oci_image_paths, self.image_uris, self.data_dir
        )

        return self._compare(
            f"{self.oci_runtime_paths[0]}/rootfs",
            f"{self.oci_runtime_paths[1]}/rootfs",
            "_compare_files",
        )

    def _compare(
        self: "DiffCommand", path1: str, path2: str, source: str
    ) -> bool:
        """Compares either OCI images or OCI runtime bundles."""
        cmd = build_diffoscope_command(
            self.output_dir,
            self.diffoscope_output_file_name,
            path1,
            path2,
            self.compare_level,
        )
        try:
            subprocess.run(cmd, check=True)  # noqa: S603
        except subprocess.CalledProcessError as e:
            if e.returncode == 1:
                # Diffoscope returns 1 on differences, so this is normal
                pass
            else:
                logger.exception(f"Failed: Diff.{source}")
                return False

        with Path(
            self.output_dir + "/" + self.diffoscope_output_file_name,
        ).open() as raw_diff_file:
            diffoscope_json = json.load(raw_diff_file)

        unknown, trivial, nontrivial, diff_list = parse_diffoscope_output(
            diffoscope_json, self.flags
        )

        # Compare image's config files.
        config_diffs = metadata_diff.compare_metadata(
            Path(self.oci_image_paths[0]), Path(self.oci_image_paths[1]), []
        )

        self._process_and_save_results(
            Path(path1),
            Path(path2),
            unknown,
            trivial,
            nontrivial,
            diff_list,
            config_diffs,
        )

        return True

    def _write_to_files(
        self: "DiffCommand",
        unknown_failure_count: int,
        trivial_failure_count: int,
        nontrivial_failure_count: int,
        diffs: list[dict[str, Any]],
        config_diffs: list[dict[str, Any]],
        files_summary: list[dict[str, Any]],
        checksum_summary: dict[str, Any],
    ) -> None:
        """Writes all diff output to files.

        Takes in the count of failures and the list of diffs. Separates out the
        unified diffs, assigns them an ID, and writes those to a separate
        file.

        Args:
            unknown_failure_count: Count of unknown failures
            trivial_failure_count: Count of trivial flagged failures
            nontrivial_failure_count: Count of non-trivial flagged failures
            diffs: List of diffs, each being a dict item returned
                    from Diff.to_slim_dict()
            config_diffs: List of diffs between image config files.
            files_summary: File analysis of trivial/nontrivial failure
            checksum_summary: File checksum comparison result summary
        Returns:
            None
        """
        unified_diff_id = 1
        unified_diff_dict = {}
        flagged_failure_count = (
            trivial_failure_count + nontrivial_failure_count
        )

        for diff in diffs:
            unified_diff_dict[unified_diff_id] = diff["unified_diff"]
            diff["unified_diff_id"] = unified_diff_id
            unified_diff_id += 1
            diff.pop("unified_diff")

        summary_json = {
            "summary": {
                "failure_summary": {
                    "unknown_failures": unknown_failure_count,
                    "trivial_failures": trivial_failure_count,
                    "nontrivial_failures": nontrivial_failure_count,
                    "flagged_failures": flagged_failure_count,
                    "total_failures": unknown_failure_count
                    + flagged_failure_count,
                },
                "checksum summary": {
                    "total_image1_file_count": checksum_summary.get(
                        "total_common_files", 0
                    )
                    + len(checksum_summary.get("only_in_image1", [])),
                    "total_image2_file_count": checksum_summary.get(
                        "total_common_files", 0
                    )
                    + len(checksum_summary.get("only_in_image2", [])),
                    "total_common_files": checksum_summary.get(
                        "total_common_files", 0
                    ),
                    "identical_file_count": len(
                        checksum_summary.get("checksum_matches", [])
                    ),
                    "trivial_checksum_different_file_count": sum(
                        len(entry.get("trivial_checksum_different_files", []))
                        for entry in files_summary or []
                    ),
                    "nontrivial_checksum_different_file_count": sum(
                        len(
                            entry.get(
                                "nontrivial_checksum_different_files", []
                            )
                        )
                        for entry in files_summary or []
                    ),
                    "only_in_image1_file_count": len(
                        checksum_summary.get("only_in_image1", [])
                    ),
                    "only_in_image2_file_count": len(
                        checksum_summary.get("only_in_image2", [])
                    ),
                },
            },
            "files": files_summary or [],
            "diffs": diffs,
            "config_diffs": config_diffs,
        }

        output_dir = self.output_dir + "/"

        with Path(str(output_dir) + self.summary_output_file_name).open(
            "w",
        ) as outfile:
            outfile.write(json.dumps(summary_json, indent=4))

        with Path(str(output_dir) + self.unified_diff_output_file_name).open(
            "w",
        ) as outfile:
            outfile.write(json.dumps(unified_diff_dict, indent=4))

    def _compare_diffoscope_and_checksum_json(self):
        """
        If two JSON files are provided, and one is named checksum_metadata.json,
        run the comparison and return the result. Otherwise, log an error and return False.
        """
        path1, path2 = self.input_files[0], self.input_files[1]
        file1, file2 = Path(path1).name, Path(path2).name

        if (
            file1 != self.CHECKSUM_METADATA_FILENAME
            and file2 != self.CHECKSUM_METADATA_FILENAME
        ):
            logger.error(
                "When providing two JSON files, one must be a checksum_metadata.json file."
            )
            return False

        logger.info("Started json comparison")
        checksum_json_path = (
            path1 if file1 == self.CHECKSUM_METADATA_FILENAME else path2
        )
        diffoscope_json_path = (
            path2 if file1 == self.CHECKSUM_METADATA_FILENAME else path1
        )

        # Load checksum metadata first so we can pass filetype lookups to the parser
        hashed_files1, hashed_files2, image1_path, image2_path = (
            load_checksum_metadata(checksum_json_path)
        )
        filetype_lookup1 = {k: v.filetype for k, v in hashed_files1.items()}
        filetype_lookup2 = {k: v.filetype for k, v in hashed_files2.items()}

        with Path(diffoscope_json_path).open() as f:
            diffoscope_json = json.load(f)

        unknown, trivial, nontrivial, diff_list = parse_diffoscope_output(
            diffoscope_json,
            self.flags,
            filetype_lookup1=filetype_lookup1,
            filetype_lookup2=filetype_lookup2,
        )

        files_summary, checksum_summary = generate_filesummary_and_checksum(
            diff_list,
            hashed_files1=hashed_files1,
            hashed_files2=hashed_files2,
            image1_path=image1_path,
            image2_path=image2_path,
        )

        config_diffs: list[dict[str, Any]] = []
        self._write_to_files(
            unknown,
            trivial,
            nontrivial,
            diff_list,
            config_diffs,
            files_summary,
            checksum_summary,
        )
        logger.info("Finished json comparison")
        return True

    def _process_and_save_results(
        self,
        image1_path: Path,
        image2_path: Path,
        unknown: int,
        trivial: int,
        nontrivial: int,
        diff_list: list[dict[str, Any]],
        config_diffs: list[dict[str, Any]],
    ):
        """
        Processes image diff results, generates and saves checksum metadata and summaries,
        and writes final output files.

        Steps for processing diffoscope output:
        - Hash the contents of each root filesystem
        - Save a checksum metadata file with hash results for both images
        - Generate summary for file and checksum differences
        - Write summary output to files

        Args:
            image1_path (Path): Path to the first image's OCI image folder or unpacked OCI filesystem
            image2_path (Path): Path to the second image's OCI image folder or unpacked OCI filesystem
            unknown: Count of unknown differences (from diffoscope parsing)
            trivial: Count of trivial differences (from diffoscope parsing)
            nontrivial: Count of nontrivial differences (from diffoscope parsing)
            diff_list: List of detailed differences returned by diffoscope
            config_diffs: List of differences between image config files.
        """
        hashed_files1 = hash_folder_contents(image1_path)
        hashed_files2 = hash_folder_contents(image2_path)

        metadata_path = str(
            Path(self.output_dir) / self.CHECKSUM_METADATA_FILENAME
        )

        save_checksum_metadata(
            metadata_path,
            hashed_files1,
            hashed_files2,
            image1_path=str(image1_path),
            image2_path=str(image2_path),
        )

        self._generate_and_save_summary(
            hashed_files1,
            hashed_files2,
            str(image1_path),
            str(image2_path),
            unknown,
            trivial,
            nontrivial,
            diff_list,
            config_diffs,
        )

    def _generate_and_save_summary(
        self,
        hashed_files1: dict[str, FileHash],
        hashed_files2: dict[str, FileHash],
        image1_path: str,
        image2_path: str,
        unknown: int,
        trivial: int,
        nontrivial: int,
        diff_list: list[dict[str, Any]],
        config_diffs: list[dict[str, Any]],
    ):
        """Generates remaining data and creates summary file."""

        files_summary, checksum_summary = generate_filesummary_and_checksum(
            diff_list,
            hashed_files1=hashed_files1,
            hashed_files2=hashed_files2,
            image1_path=image1_path,
            image2_path=image2_path,
        )

        self._write_to_files(
            unknown,
            trivial,
            nontrivial,
            diff_list,
            config_diffs,
            files_summary,
            checksum_summary,
        )
