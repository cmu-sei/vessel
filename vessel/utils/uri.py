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

"""Utility class for image URI."""


class ImageURI:
    """Class to represent data of an image URI."""

    def __init__(
        self: "ImageURI",
        container_transport: str,
    ) -> None:
        """Initializer for ImageURI class."""
        self.container_transport = container_transport
        self.image_name, self.tag = parse_container_transport(
            container_transport,
        )
        self.output_identifier = f"{self.image_name}.{self.tag}"


def parse_container_transport(container_transport: str) -> tuple[str, str]:
    """Parse skopeo path to return image name and tag.

    Parses a skopeo path to return the image name and the tag. Uses latest
    as a tag if none is found.

    Args:
        container_transport: transport path as defined here,
        https://github.com/containers/image/blob/main/docs/containers-transports.5.md

    Returns:
        Tuple with image name and tag
    """
    image_name = ""
    tag = ""
    split_path = (
        container_transport.split(":", 1)[-1].split("/")[-1].split(":", 1)
    )

    # Case when there is no tag on the end of the path.
    # Must append latest tag as skopeo strips it out if not specified and
    #   umoci requires a tag to unpack.
    if len(split_path) == 1:
        image_name = f"{split_path[0]}"
        tag = "latest"
    # Case when there is a tag at the end of the path
    # Append tag to name to ensure unique folders are created.
    else:
        image_name = f"{split_path[0]}"
        tag = split_path[1]

    return image_name, tag
