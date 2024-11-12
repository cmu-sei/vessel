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

import subprocess
import sys
from logging import getLogger

from vessel.utils.uri import ImageURI

logger = getLogger(__name__)


def skopeo_copy(image_uri: "ImageURI", output_path: str) -> str:
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

    try:
        subprocess.run(
            [
                "/usr/bin/skopeo",
                "copy",
                image_uri.container_transport,
                f"oci:{dest_path}:{image_uri.tag}",
            ],
            check=True,
        )
    except subprocess.CalledProcessError:
        sys.exit(1)

    return dest_path
