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

"""Utility umoci funcitons."""

import subprocess
import sys
from logging import getLogger

from vessel.utils.uri import ImageURI

logger = getLogger(__name__)

UMOCI_UNPACK_PATH = "/umoci-unpack-"

def umoci_unpack(
    oci_image_paths: list[str], image_uris: list[ImageURI], data_dir: str
) -> list[str]:
    """
    Executes umoci to unpack an OCI image into an OCI runtime bundle with a unified file system.

    Args:
        oci_image_paths: A list of paths to OCI image folders.
        image_uris: The URI where the OCI image was obtained from.
        data_dir: The base folder where we are working on.

    Returns:
        The results of the command execution.
    """
    oci_runtime_paths: list[str] = []

    for unpack_path, uri in zip(
        oci_image_paths,
        image_uris,
        strict=True,
    ):
        umoci_output_path = f"{data_dir}{UMOCI_UNPACK_PATH}{uri.output_identifier}"
        oci_runtime_paths.append(umoci_output_path)

        run_umoci(
            "unpack",
            ["--image", f"{unpack_path}:{uri.tag}", umoci_output_path],
        )

    return oci_runtime_paths


def run_umoci(
    command: str, args: list[str]
) -> subprocess.CompletedProcess[str]:
    """Executes the given umoci command.

    Args:
        command: The umoci command to run.
        args: Arguments for umoci.

    Returns:
        The results of the command execution.
    """
    runtime = "/usr/bin/umoci"
    try:
        command_list = [runtime, command]
        for arg in args:
            command_list.append(f"{arg}")

        return subprocess.run(
            command_list, capture_output=True, text=True, check=True
        )
    except subprocess.CalledProcessError as e:
        print(f"Error: {e} - stderr: {e.stderr}")
        sys.exit(1)
