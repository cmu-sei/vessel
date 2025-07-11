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
import sys
import tempfile
from logging import getLogger
from pathlib import Path
from typing import Any

import yaml

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

    def __init__(
        self: "DiffCommand",
        input_files: list[str],
        compare_level: str,
        data_dir: str,
        output_dir: str,
        file_checksum: bool,
    ) -> None:
        """Initializer for a diff operation.

        Processes command-line arguments.
        """
        self.flags: list[Flag] = []
        self.input_files: list[str] = input_files
        self.compare_level: str = compare_level
        self.data_dir: str = data_dir
        self.output_dir: str = output_dir
        self.file_checksum: bool = file_checksum
        self.temp_dir: tempfile.TemporaryDirectory[str] | None = None
        self.image_uris: list[ImageURI] = []
        self.unpacked_image_paths: list[str] = []
        self.umoci_image_paths: list[str] = []
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
            logger.error("No inputs provided. Acceptable values are 1 or 2")
            return False

        if len(self.input_files) == 1:
            return self.compare_diffoscope_json()

        if len(self.input_files) > 2:
            logger.error(
                "Too many inputs provided. Acceptable values are 1 or 2",
            )
            return False

        logger.info("Images to be compared:")
        logger.info("- %s", self.input_files[0])
        logger.info("- %s", self.input_files[1])

        if not self._unpack_images():
            return False

        if self.compare_level == "image":
            return self._compare_images()

        if get_manifest_digest(
            self.unpacked_image_paths[0],
        ) == get_manifest_digest(self.unpacked_image_paths[1]):
            logger.info("All layers are identical")
            self.write_to_files(0, 0, 0, [], [], {})
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

    def _unpack_images(self: "DiffCommand") -> bool:
        """Unpacks images to data folder with skopeo."""
        self.image_uris = [
            ImageURI(container_transport)
            for container_transport in self.input_files
        ]

        if (self.image_uris[0].output_identifier == self.image_uris[1].output_identifier):  # noqa: E501 # fmt: skip
            self.image_uris[0].output_identifier = f"{self.image_uris[0].output_identifier}_0"  # noqa: E501 # fmt: skip
            self.image_uris[1].output_identifier = f"{self.image_uris[1].output_identifier}_1"  # noqa: E501 # fmt: skip

        self.unpacked_image_paths = [
            skopeo_copy(image_path, self.data_dir)
            for image_path in self.image_uris
        ]

        return True

    def _compare_images(self: "DiffCommand") -> bool:
        """Compares two images directly.

        Returns:
            True on success, else False
        """
        cmd = build_diffoscope_command(
            self.output_dir,
            self.diffoscope_output_file_name,
            self.unpacked_image_paths[0],
            self.unpacked_image_paths[1],
            self.compare_level,
        )
        try:
            subprocess.run(cmd, check=True)  # noqa: S603
        except subprocess.CalledProcessError as e:
            if e.returncode == 1:
                # Diffoscope returns 1 on differences, so this is normal
                pass
            else:
                logger.exception("Failed: Diff.compare_images")
                return False

            with Path(
                self.output_dir + "/" + self.diffoscope_output_file_name,
            ).open() as raw_diff_file:
                diffoscope_json = json.load(raw_diff_file)

        (
            unknown_failures_count,
            trivial_failures_count,
            nontrivial_failures_count,
            diff_list,
            files_summary,
            checksum_summary,
        ) = parse_diffoscope_output(
            diffoscope_json,
            self.flags,
            file_checksum=self.file_checksum,
        )
        self.write_to_files(
            unknown_failures_count,
            trivial_failures_count,
            nontrivial_failures_count,
            diff_list,
            files_summary,
            checksum_summary,
        )

        return True

    def _compare_files(self: "DiffCommand") -> bool:
        """Compare final image filesystem.

        Compares file-by-file after unpacking image into the final
        image filesystem.

        Returns:
            True on success, else False
        """
        for unpack_path, uri in zip(
            self.unpacked_image_paths,
            self.image_uris,
            strict=True,
        ):
            umoci_output_path = (
                f"{self.data_dir}/umoci-unpack-{uri.output_identifier}"
            )
            self.umoci_image_paths.append(umoci_output_path)

            try:
                subprocess.run(
                    [  # noqa: S603
                        "/usr/bin/umoci",
                        "unpack",
                        "--image",
                        f"{unpack_path}:{uri.tag}",
                        umoci_output_path,
                    ],
                    check=True,
                )
            except subprocess.CalledProcessError:
                sys.exit(1)

        cmd = build_diffoscope_command(
            self.output_dir,
            self.diffoscope_output_file_name,
            f"{self.umoci_image_paths[0]}/rootfs",
            f"{self.umoci_image_paths[1]}/rootfs",
            self.compare_level,
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
            self.output_dir + "/" + self.diffoscope_output_file_name,
        ).open() as raw_diff_file:
            diffoscope_json = json.load(raw_diff_file)

        (
            unknown_failures_count,
            trivial_failures_count,
            nontrivial_failures_count,
            diff_list,
            files_summary,
            checksum_summary,
        ) = parse_diffoscope_output(
            diffoscope_json,
            self.flags,
            file_checksum=self.file_checksum,
        )
        self.write_to_files(
            unknown_failures_count,
            trivial_failures_count,
            nontrivial_failures_count,
            diff_list,
            files_summary,
            checksum_summary,
        )

        return True

    def compare_diffoscope_json(self: "DiffCommand") -> bool:
        """Parses diffoscope json when file provided directly.

        Returns:
            True on success
        """
        with Path(self.input_files[0]).open() as raw_diff_file:
            diffoscope_json = json.load(raw_diff_file)

        (
            unknown_failures_count,
            trivial_failures_count,
            nontrivial_failures_count,
            diff_list,
            files_summary,
            checksum_summary,
        ) = parse_diffoscope_output(
            diffoscope_json,
            self.flags,
            file_checksum=self.file_checksum,
        )
        self.write_to_files(
            unknown_failures_count,
            trivial_failures_count,
            nontrivial_failures_count,
            diff_list,
            files_summary,
            checksum_summary,
        )

        return True

    def write_to_files(
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
        flagged_failure_count = trivial_failure_count + nontrivial_failure_count

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
                    "total_failures": unknown_failure_count + flagged_failure_count,
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

        with Path(str(output_dir) + self.summary_output_file_name).open(
            "w",
        ) as outfile:
            outfile.write(json.dumps(summary_json, indent=4))

        with Path(str(output_dir) + self.unified_diff_output_file_name).open(
            "w",
        ) as outfile:
            outfile.write(json.dumps(unified_diff_dict, indent=4))
