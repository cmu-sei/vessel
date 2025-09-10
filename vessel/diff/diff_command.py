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
from vessel.diff.helpers.failure import FailureSummary
from vessel.diff.helpers.metadata_diff import MetadataDiffs
from vessel.utils import oci, umoci
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
from vessel.utils.skopeo import skopeo_copy
from vessel.utils.uri import ImageURI

logger = getLogger(__name__)


class DiffCommand:
    """Class that setups up and executes a diff operation."""

    DIFF_CONFIG_FILEPATH = "../config/diff_config.yaml"
    CHECKSUM_METADATA_FILENAME = "checksum_metadata.json"
    DIFFOSCOPE_OUTPUT_FILENAME = "diffoscope_output.json"
    SUMMARY_OUTPUT_FILENAME = "summary.json"
    UNIFIED_DIFF_OUTPUT_FILENAME = "unified_diffs.json"
    METADATA_DIFF_OUTPUT_FILENAME = "meta_diffs.json"

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
        self.meta_flags: list[metadata_diff.MetadataFlag] = []
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
        try:
            self._setup()

            if self.mode == "json":
                return self._compare_json_diff_outputs()
            elif self.mode == "image" or self.mode == "file":
                if all(f.endswith(".json") for f in self.input_files):
                    raise RuntimeError(
                        "JSON files detected but mode is not 'json' "
                        "Please rerun with -m json"
                    )

                if len(self.input_files) != 2:
                    raise RuntimeError(
                        "Two image paths are required for image or file mode."
                    )

                logger.info("Images to be compared:")
                logger.info("- %s", self.input_files[0])
                logger.info("- %s", self.input_files[1])

                self._convert_to_oci()

                # Quick check to avoid detailed image comparison if manifests are the same.
                if oci.get_manifest_digest(
                    self.oci_image_paths[0]
                ) == oci.get_manifest_digest(self.oci_image_paths[1]):
                    logger.info("Both images are identical")
                    self._write_to_files(
                        FailureSummary(),
                        FailureSummary(),
                        FailureSummary(),
                        [],
                        MetadataDiffs(),
                        [],
                        {},
                    )
                    return True

                if self.mode == "image":
                    return self._compare_images()
                elif self.mode == "file":
                    return self._compare_files()

            # If we get here, invalid mode was provided.
            raise RuntimeError(
                "Invalid mode selected. Choose from: image, file, json"
            )
        except RuntimeError as e:
            logger.error(str(e))
            return False

    def _setup(self: "DiffCommand"):
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

        # Load configuration.
        with Path.open(
            Path(Path(__file__).resolve()).parent
            / DiffCommand.DIFF_CONFIG_FILEPATH,
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
                self.meta_flags = metadata_diff.load_flags(config["metaflags"])
            except yaml.YAMLError:
                raise RuntimeError("Error reading the yaml config file.")

    def _compare_json_diff_outputs(self) -> bool:
        """
        Used for comparing outputs of a previous Vessel diff run without calculating the diff again.
        If JSON files are provided, and they have the expected names,
        run the comparison and return the result. Otherwise, log an error and return False.
        """
        # Figure out paths for each type of JSON input file.
        diffoscope_json_path, checksum_json_path, metadata_json_path = (
            self._parse_json_input_files()
        )

        # Load checksum and get filetype lookups that the parser will need
        hashed_files1, hashed_files2, image1_path, image2_path = (
            load_checksum_metadata(checksum_json_path)
        )
        filetype_lookup1 = {k: v.filetype for k, v in hashed_files1.items()}
        filetype_lookup2 = {k: v.filetype for k, v in hashed_files2.items()}

        # Load metadata diffs.
        meta_diffs = MetadataDiffs.load_from_file(Path(metadata_json_path))

        # Call common method to parse diffs and generate output.
        self._process_and_save_results(
            image1_path=Path(image1_path),
            image2_path=Path(image2_path),
            diffoscope_output_path=Path(diffoscope_json_path),
            meta_diffs=meta_diffs,
            hashed_files1=hashed_files1,
            hashed_files2=hashed_files2,
            filetype_lookup1=filetype_lookup1,
            filetype_lookup2=filetype_lookup2,
        )

        return True

    def _parse_json_input_files(self) -> tuple[str, str, str]:
        """Parses the JSON input files to identify which is which."""
        if len(self.input_files) != 3:
            raise RuntimeError(
                f"Three JSON files are needed for JSON comparison mode ({self.DIFFOSCOPE_OUTPUT_FILENAME}, {self.CHECKSUM_METADATA_FILENAME} and {self.METADATA_DIFF_OUTPUT_FILENAME})"
            )

        diffoscope_json_path = ""
        checksum_json_path = ""
        metadata_json_path = ""

        for input_file in self.input_files:
            input_file_name = Path(input_file).name
            if input_file_name == self.DIFFOSCOPE_OUTPUT_FILENAME:
                diffoscope_json_path = input_file
            elif input_file_name == self.CHECKSUM_METADATA_FILENAME:
                checksum_json_path = input_file
            elif input_file_name == self.METADATA_DIFF_OUTPUT_FILENAME:
                metadata_json_path = input_file

        if (
            diffoscope_json_path == ""
            or checksum_json_path == ""
            or metadata_json_path == ""
        ):
            raise RuntimeError(
                f"At least one of the JSON input files did not have its expected names. The following names need to be used: {self.DIFFOSCOPE_OUTPUT_FILENAME}, {self.CHECKSUM_METADATA_FILENAME} and {self.METADATA_DIFF_OUTPUT_FILENAME}"
            )

        return diffoscope_json_path, checksum_json_path, metadata_json_path

    def _convert_to_oci(self: "DiffCommand"):
        """Converts images to an OCI data folder with skopeo."""
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

    def _compare_images(self: "DiffCommand") -> bool:
        """Compares two images directly.

        Returns:
            True on success, else False
        """

        return self._compare(
            Path(self.oci_image_paths[0]), Path(self.oci_image_paths[1])
        )

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
            Path(f"{self.oci_runtime_paths[0]}/rootfs"),
            Path(f"{self.oci_runtime_paths[1]}/rootfs"),
        )

    def _compare(
        self: "DiffCommand", image1_path: Path, image2_path: Path
    ) -> bool:
        """Compares the given image folders.

        Args:
            image1_path, image2_path: paths to folders with files from OCI
            images, either in image spec or runtime bundles.

        Returns:
            True on success, else False
        """
        # First hash files.
        hashed_files1, hashed_files2 = self._hash_and_write_checksum_metadata(
            image1_path, image2_path
        )

        # Execute diffoscope.
        cmd = build_diffoscope_command(
            self.output_dir,
            self.DIFFOSCOPE_OUTPUT_FILENAME,
            str(image1_path),
            str(image2_path),
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

        # Execute OCI image metadata comparison.
        meta_diffs = metadata_diff.compare_metadata(
            Path(self.oci_image_paths[0]), Path(self.oci_image_paths[1])
        )

        # Call common method to parse diffs and generate output.
        diffoscope_output_path = Path(
            self.output_dir,
            self.DIFFOSCOPE_OUTPUT_FILENAME,
        )
        self._process_and_save_results(
            image1_path=image1_path,
            image2_path=image2_path,
            diffoscope_output_path=diffoscope_output_path,
            meta_diffs=meta_diffs,
            hashed_files1=hashed_files1,
            hashed_files2=hashed_files2,
        )

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

        checksum_path = str(
            Path(self.output_dir) / self.CHECKSUM_METADATA_FILENAME
        )

        write_checksum_metadata(
            checksum_path,
            hashed_files1,
            hashed_files2,
            image1_path=str(image1_path),
            image2_path=str(image2_path),
        )
        return hashed_files1, hashed_files2

    def _process_and_save_results(
        self,
        image1_path: Path,
        image2_path: Path,
        diffoscope_output_path: Path,
        meta_diffs: MetadataDiffs,
        hashed_files1: dict[str, Any],
        hashed_files2: dict[str, Any],
        filetype_lookup1: dict[str, str] | None = None,
        filetype_lookup2: dict[str, str] | None = None,
    ) -> None:
        """
        Parses both diffoscope and metadata/config diffs, creates summaries and writes outputs.

        Args:
            image1_path, image2_path: Path to first and second image filesystem
            diffoscope_output_path: The path to diffoscope output JSON
            hashed_files1, hashed_files2: Hashes file info for both images
            filetype_lookup1, filetype_lookup2: Filetype info for both images
        """
        # First load diffoscope output and parse it for diffs.
        with diffoscope_output_path.open() as raw_diff_file:
            diffoscope_json = json.load(raw_diff_file)
        unknown, trivial, nontrivial, diff_list = parse_diffoscope_output(
            diffoscope_json,
            self.flags,
            filetype_lookup1=filetype_lookup1,
            filetype_lookup2=filetype_lookup2,
        )
        file_failure_summary = FailureSummary(unknown, trivial, nontrivial)

        # Now check flags for image metadata diffs.
        meta_diffs, meta_summary = metadata_diff.match_flags(
            meta_diffs, self.meta_flags
        )

        # Create totals with metadata/config failures.
        total_failure_summary = FailureSummary(
            unknown_failure_count=file_failure_summary.unknown_failures
            + meta_summary.unknown_failures,
            trivial_failure_count=file_failure_summary.trivial_failures
            + meta_summary.trivial_failures,
            nontrivial_failure_count=file_failure_summary.nontrivial_failures
            + meta_summary.nontrivial_failures,
        )

        # Create summaries for hashes and checksum.
        files_summary, checksum_summary = generate_filesummary_and_checksum(
            diff_list,
            hashed_files1=hashed_files1,
            hashed_files2=hashed_files2,
            image1_path=str(image1_path),
            image2_path=str(image2_path),
        )

        # Write outputs to files.
        self._write_to_files(
            total_failure_summary=total_failure_summary,
            file_failure_summary=file_failure_summary,
            meta_failure_summary=meta_summary,
            diffs=diff_list,
            meta_diffs=meta_diffs,
            files_summary=files_summary,
            checksum_summary=checksum_summary,
        )

    def _write_to_files(
        self: "DiffCommand",
        total_failure_summary: FailureSummary,
        file_failure_summary: FailureSummary,
        meta_failure_summary: FailureSummary,
        diffs: list[dict[str, Any]],
        meta_diffs: MetadataDiffs,
        files_summary: list[dict[str, Any]],
        checksum_summary: dict[str, Any],
    ) -> None:
        """Writes all diff output to files.

        Takes in the count of failures and the list of diffs. Separates out the
        unified diffs, assigns them an ID, and writes those to a separate
        file.

        Args:
            total_failure_summary: Summary of all failures in comparison
            file_failure_summary: Summary of failures in file comparison
            meta_failure_summary: Summary of failures in metadata/config comparison
            diffs: List of diffs, each being a dict item returned
                    from Diff.to_slim_dict()
            meta_diffs: List of diffs between OCI images metadata/configs.
            files_summary: File analysis of trivial/nontrivial failure
            checksum_summary: File checksum comparison result summary
        Returns:
            None
        """
        unified_diff_id = 1
        unified_diff_dict = {}

        for diff in diffs:
            unified_diff_dict[unified_diff_id] = diff["unified_diff"]
            diff["unified_diff_id"] = unified_diff_id
            unified_diff_id += 1
            diff.pop("unified_diff")

        summary_json = {
            "summary": {
                "total_failure_summary": total_failure_summary.to_dict(),
                "file_failure_summary": file_failure_summary.to_dict(),
                "meta_failure_summary": meta_failure_summary.to_dict(),
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
            "meta_diffs": meta_diffs.to_dict_list(),
        }

        with Path(self.output_dir, self.SUMMARY_OUTPUT_FILENAME).open(
            "w",
        ) as outfile:
            outfile.write(json.dumps(summary_json, indent=4))

        with Path(self.output_dir, self.UNIFIED_DIFF_OUTPUT_FILENAME).open(
            "w",
        ) as outfile:
            outfile.write(json.dumps(unified_diff_dict, indent=4))

        with Path(self.output_dir, self.METADATA_DIFF_OUTPUT_FILENAME).open(
            "w",
        ) as outfile:
            outfile.write(json.dumps(meta_diffs.to_dict_list(), indent=4))
