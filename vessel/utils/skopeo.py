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

"""Utility skopeo funcitons."""

import json
import subprocess
import sys
from logging import getLogger
from typing import Any

from vessel.utils.uri import ImageURI

logger = getLogger(__name__)


def skopeo_copy(image_uri: ImageURI, output_path: str) -> str:
    """Skopeo copies image to specific directory.

    Uses skopeo copy to take images from image path and then
    copies it into the output path in the oci format.

    Args:
        image_uri: Path of the image
        output_path: Path to copy the image to

    Returns:
        Path to the directory containing the oci image
    """
    dest_path = f"{output_path}/{image_uri.output_identifier}"

    run_skopeo(
        "copy",
        args=[
            image_uri.container_transport,
            f"oci:{dest_path}:{image_uri.tag}",
        ],
    )

    return dest_path


def skopeo_get_config(image_uri: ImageURI) -> dict[str, Any]:
    """Uses skopeo to get the metadata/config file of an OCI image.

    Args:
        image_uri: Path of the image

    Returns:
        A dictionary with the metadata fields.
    """

    # Run skopeo inspect to get the config.
    result = run_skopeo("inspect", args=["--config", f"{image_uri}"])

    # Load as a dict and return.
    return json.loads(result.stdout)


def run_skopeo(
    command: str, args: list[str]
) -> subprocess.CompletedProcess[str]:
    """Executes the given Skopeo command.

    Args:
        command: The skopeo command to run.
        args: Arguments for skopeo.

    Returns:
        The results of the command execution.
    """
    skopeo_runtime = "/usr/bin/skopeo"
    try:
        command_list = [skopeo_runtime, command]
        for arg in args:
            command_list.append(f"{arg}")

        return subprocess.run(
            command_list, capture_output=True, text=True, check=True
        )
    except subprocess.CalledProcessError as e:
        print(f"Error: {e} - stderr: {e.stderr}")
        sys.exit(1)
