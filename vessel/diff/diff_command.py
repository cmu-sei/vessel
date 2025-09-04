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

from vessel.utils import umoci
from vessel.utils.checksum import (
    generate_filesummary_and_checksum,
    hash_folder_contents,
    load_checksum_metadata,
    write_checksum_metadata,
)
from vessel.utils.diffoscope import (
    build_diffoscope_command,
    parse_diffoscope_output,
)
from vessel.utils.flag import Flag
from vessel.utils.oci import get_manifest_digest
from vessel.utils.skopeo import skopeo_copy
from vessel.utils.uri import ImageURI

logger = getLogger(__name__)


class DiffCommand:
    """Class that setups up and executes a diff operation."""

    CHECKSUM_METADATA_FILENAME = "checksum_metadata.json"
    DIFFOSCOPE_OUTPUT_FILENAME = "diffoscope_output.json"
    SUMMARY_OUTPUT_FILENAME = "summary.json"
    UNIFIED_DIFF_OUTPUT_FILENAME = "unified_diffs.json"

    def __init__(
        self: "DiffCommand",
        input_files: list[str],
        data_dir: str,
        mode: str,
        output_dir: str,
    ) -> None:
        """Initializer for a diff operation.

        Processes command-line arguments.
        """
        self.flags: list[Flag] = []
        self.input_files: list[str] = input_files
        self.mode: str = mode
        self.data_dir: str = data_dir
        self.output_dir: str = output_dir
        self.temp_dir: tempfile.TemporaryDirectory[str] | None = None
        self.image_uris: list[ImageURI] = []
        self.oci_image_paths: list[str] = []
        self.oci_runtime_paths: list[str] = []

    def execute(self: "DiffCommand") -> bool:
        """Executes a diff operation.

        Returns:
            True on success, else False
        """
        if not self._setup():
            return False

        if len(self.input_files) < 2:
            logger.error(
                "At least 2 inputs required. Acceptable values are 2 image paths, "
                "or 2 JSON files (diffoscope output and checksum metadata)"
            )
            return False

        if len(self.input_files) > 2:
            logger.error(
                "Too many inputs provided. Acceptable values are 2 image paths, "
                "or 2 JSON files (diffoscope output and checksum metadata)"
            )
            return False

        if all(f.endswith(".json") for f in self.input_files):
            if self.mode != "json":
                logger.error(
                    "Two JSON files detected but mode is not 'json' "
                    "Please rerun with -m json"
                )
                return False
            return self._compare_diffoscope_and_checksum_json()

        # Image or file mode
        logger.info("Images to be compared:")
        logger.info("- %s", self.input_files[0])
        logger.info("- %s", self.input_files[1])

        if not self._unpack_images():
            return False

        if self.mode == "image":
            return self._compare_images()

        if get_manifest_digest(self.oci_image_paths[0]) == get_manifest_digest(
            self.oci_image_paths[1]
        ):
            logger.info("All layers are identical")
            self._write_to_files(0, 0, 0, [], [], {})
            return True

        if self.mode == "file":
            return self._compare_files()

        logger.error("Invalid mode selected. Choose from: image, file, json")
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

    def _unpack_images(self: "DiffCommand") -> bool:
        """Unpacks images to data folder with skopeo."""
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
        return self._compare(self.oci_image_paths[0], self.oci_image_paths[1])

    def _compare_files(self: "DiffCommand") -> bool:
        """Compare final image filesystem.

        Compares file-by-file after unpacking image into the final
        image filesystem.

        Returns:
            True on success, else False
        """
        self.oci_runtime_paths = umoci.umoci_unpack(
            self.oci_image_paths, self.image_uris, self.data_dir
        )

        return self._compare(
            f"{self.oci_runtime_paths[0]}/rootfs",
            f"{self.oci_runtime_paths[2]}/rootfs",
        )

    def _compare(
        self: "DiffCommand", image1_path: str, image2_path: str
    ) -> bool:
        """Compares the given image folders.

        Args:
            image1_path, image2_path: paths to folders with files from OCI
            images, either in image spec or runtime bundles.

        Returns:
            True on success, else False
        """
        cmd = build_diffoscope_command(
            self.output_dir,
            self.DIFFOSCOPE_OUTPUT_FILENAME,
            image1_path,
            image2_path,
            self.mode,
        )
        try:
            subprocess.run(cmd, check=True)  # noqa: S603
        except subprocess.CalledProcessError as e:
            if e.returncode == 1:
                # Diffoscope returns 1 on differences, so this is normal
                pass
            else:
                logger.exception("Failed: Diff.compare_files")
                return False

        with Path(
            self.output_dir + "/" + self.DIFFOSCOPE_OUTPUT_FILENAME,
        ).open() as raw_diff_file:
            diffoscope_json = json.load(raw_diff_file)

        unknown, trivial, nontrivial, diff_list = parse_diffoscope_output(
            diffoscope_json, self.flags
        )

        self._process_and_save_results(
            Path(image1_path),
            Path(image2_path),
            diff_list,
            unknown,
            trivial,
            nontrivial,
        )

        return True

    def _write_to_files(
        self: "DiffCommand",
        unknown_failure_count: int,
        trivial_failure_count: int,
        nontrivial_failure_count: int,
        diffs: list,
        files_summary: list[dict[str, Any]],
        checksum_summary: dict[Any, Any],
    ) -> None:
        """Writes all diff output to files.

        Takes in the count of failures and the list of diffs. Separates out the
        unified diffs, assigns them an ID, and writes those to a separate
        file.

        Args:
            unknown_failure_count: Count of unknown failures
            flagged_failure_count: Count of flagged failures
            diffs: List of diffs, each being a dict item returned
                    from Diff.to_slim_dict()
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
        }

        output_dir = self.output_dir + "/"

        with Path(str(output_dir) + self.SUMMARY_OUTPUT_FILENAME).open(
            "w",
        ) as outfile:
            outfile.write(json.dumps(summary_json, indent=4))

        with Path(str(output_dir) + self.UNIFIED_DIFF_OUTPUT_FILENAME).open(
            "w",
        ) as outfile:
            outfile.write(json.dumps(unified_diff_dict, indent=4))

    def _compare_diffoscope_and_checksum_json(self) -> bool:
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

        self._summarize_and_write_outputs(
            diff_list=diff_list,
            unknown_failure_count=unknown,
            trivial_failure_count=trivial,
            nontrivial_failure_count=nontrivial,
            hashed_files1=hashed_files1,
            hashed_files2=hashed_files2,
            image1_path=image1_path,
            image2_path=image2_path,
        )

        logger.info("Finished json comparison")
        return True

    def _hash_and_write_checksum_metadata(
        self,
        image1_path: Path,
        image2_path: Path,
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        """Hash both filesystems and write checksum metadata JSON

        Args:
            image1_path: Path to first image filesystem
            image2_path: Path to second image filesystem

        Returns:
            A tuple (hashed_files1, hashed_files2), where each element is a mapping
            of file path to hashed file
        """
        hashed_files1 = hash_folder_contents(image1_path)
        hashed_files2 = hash_folder_contents(image2_path)

        metadata_path = str(
            Path(self.output_dir) / self.CHECKSUM_METADATA_FILENAME
        )

        write_checksum_metadata(
            metadata_path,
            hashed_files1,
            hashed_files2,
            image1_path=str(image1_path),
            image2_path=str(image2_path),
        )
        return hashed_files1, hashed_files2

    def _summarize_and_write_outputs(
        self,
        diff_list: list[dict[str, Any]],
        unknown_failure_count: int,
        trivial_failure_count: int,
        nontrivial_failure_count: int,
        hashed_files1: dict[str, Any],
        hashed_files2: dict[str, Any],
        image1_path: str,
        image2_path: str,
    ) -> None:
        """Generate checksum summaries and write output

        Args:
            diff_list: Diffs returned by diffoscope parsing
            unknown_failure_count: Number of unknown differences
            trivial_failure_count: Number of trivial differences
            nontrivial_failure_count: Number of nontrivial differences
            hashed_files1: Hash map for image 1 (path to metadata)
            hashed_files2: Hash map for image 2 (path to metadata)
            image1_path: Path to first image filesystem
            image2_path: Path to second image filesystem
        """
        files_summary, checksum_summary = generate_filesummary_and_checksum(
            diff_list,
            hashed_files1=hashed_files1,
            hashed_files2=hashed_files2,
            image1_path=image1_path,
            image2_path=image2_path,
        )

        self._write_to_files(
            unknown_failure_count=unknown_failure_count,
            trivial_failure_count=trivial_failure_count,
            nontrivial_failure_count=nontrivial_failure_count,
            diffs=diff_list,
            files_summary=files_summary,
            checksum_summary=checksum_summary,
        )

    def _process_and_save_results(
        self,
        image1_path: Path,
        image2_path: Path,
        diff_list: list[dict[str, Any]],
        unknown_failure_count: int,
        trivial_failure_count: int,
        nontrivial_failure_count: int,
    ) -> None:
        """
        Hash image directories, save checksum metadata, summarize, and write outputs

        Args:
            image1_path: Path to first image filesystem
            image2_path: Path to second image filesystem
            diff_list: List of detailed differences returned by diffoscope parsing
            unknown_failure_count: Count of unknown differences
            trivial_failure_count: Count of trivial differences
            nontrivial_failure_count: Count of nontrivial differences
        """
        hashed_files1, hashed_files2 = self._hash_and_write_checksum_metadata(
            image1_path, image2_path
        )

        self._summarize_and_write_outputs(
            diff_list=diff_list,
            unknown_failure_count=unknown_failure_count,
            trivial_failure_count=trivial_failure_count,
            nontrivial_failure_count=nontrivial_failure_count,
            hashed_files1=hashed_files1,
            hashed_files2=hashed_files2,
            image1_path=str(image1_path),
            image2_path=str(image2_path),
        )
