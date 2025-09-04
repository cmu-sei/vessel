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

from pathlib import Path

from vessel.diff.helpers import matadata_diff
from vessel.utils import skopeo
from vessel.utils.uri import ImageURI


def test_comp(tmp_path: Path):
    """Tests that for two known images, the two known diffs are found."""
    test_image_name = "hello-world:latest"
    test_image_uri = ImageURI(f"docker://{test_image_name}")
    output_path1 = skopeo.skopeo_copy(test_image_uri, str(tmp_path))

    test_image_name = "busybox:latest"
    test_image_uri = ImageURI(f"docker://{test_image_name}")
    output_path2 = skopeo.skopeo_copy(test_image_uri, str(tmp_path))

    # flags = [MetadataFlag("TEST", "config/sh", "MID")]

    diffs = matadata_diff.compare_metadata(
        Path(output_path1), Path(output_path2), []
    )
    print(f"Diffs: {diffs}")
    # assert len(diffs) == 2

    assert False
