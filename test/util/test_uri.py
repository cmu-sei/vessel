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

"""Unit tests for the uri module."""

import pytest

from vessel.utils.uri import ImageURI, parse_container_transport

TEST_TRANSPORT_STRINGS = [
    ("docker://user/image", ("image", "latest")),
    ("docker://user/image:1.0", ("image", "1.0")),
    ("docker://image", ("image", "latest")),
    ("docker://image:1.0", ("image", "1.0")),
    ("docker-daemon:user/image", ("image", "latest")),
    ("docker-daemon:user/image:1.0", ("image", "1.0")),
    ("docker-archive:user/image", ("image", "latest")),
    ("docker-archive:user/image:1.0", ("image", "1.0")),
    ("oci:/users/images/image", ("image", "latest")),
    ("oci:/users/images/image:1.0", ("image", "1.0")),
    ("oci-archive:/users/images/image.tar", ("image.tar", "latest")),
    ("oci-archive:/users/images/image.tar:1.0", ("image.tar", "1.0")),
]


@pytest.mark.parametrize("test_input, expected", TEST_TRANSPORT_STRINGS)
def test_parse_container_transport(test_input: str, expected: tuple[str, str]):
    """Tests tha parsing works for common sample transport strings."""

    image_name, tag = parse_container_transport(test_input)

    assert (image_name, tag) == expected


@pytest.mark.parametrize("test_input, expected", TEST_TRANSPORT_STRINGS)
def test_image_uri_constructor(test_input: str, expected: tuple[str, str]):
    """Tests tha parsing works for common sample transport strings."""

    uri = ImageURI(test_input)

    assert (uri.image_name, uri.tag) == expected
    assert uri.output_identifier == f"{expected[0]}.{expected[1]}"
