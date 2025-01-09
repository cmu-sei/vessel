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

"""Unit tests for the oci module."""

import json
from pathlib import Path

from vessel.utils.oci import get_manifest_digest


def create_test_manifest(manifest_path: Path, hash: str):
    """Creates a manifest in the given file, with the given hash."""
    data = {"manifests": [{"digest": f"sha256:{hash}"}]}
    with open(manifest_path, "w") as file:
        json.dump(data, file, indent=4)


def test_get_manifest_digest(tmp_path: Path):
    """Tests that a hash can be properly obtained from a manifest file."""

    test_hash = (
        "f3b3b28a45160805bb16542c9531888519430e9e6d6ffc09d72261b0d26ff74f"
    )
    manifest_file = "index.json"
    manifest_path = tmp_path / manifest_file
    create_test_manifest(manifest_path, test_hash)

    digest = get_manifest_digest(str(tmp_path))

    assert digest == test_hash
