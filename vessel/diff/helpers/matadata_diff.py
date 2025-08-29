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

"""Compares two OCI image metadata (config) files for critical changes."""

from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Optional

from vessel.utils import oci

KEY_SEPARATOR = "/"
"""Separator used to show nested keys."""

# Critical keys to be compared.
ARCH_KEY = "architecture"
OS_KEY = "os"
CONFIG_KEY = "config"
CONFIG_SUBKEYS = [
    "User",
    "ExposedPorts",
    "Env",
    "Entrypoint",
    "Cmd",
    "Volumes",
    "WorkingDir",
]


@dataclass
class MetadataDiff:
    """An entry describing a diff in a OCI image metadata (config) file."""

    key: str
    """The full path to the key with the diff."""

    value1: Optional[Any]
    """The value of the key in the first image."""

    value2: Optional[Any]
    """The value of the key in the second image."""


@dataclass
class MetadataFlag:
    """Represents a type of issue, and the ket it is being associated to."""

    category_id: str
    """The id of the category this flag is covering."""

    key: str
    """The full path to the key with the diff."""

    severity: str
    """The severity being used to treat this case."""


def compare_metadata(
    oci_image_path1: Path, oci_image_path2: Path, flags: list[MetadataFlag]
) -> list[dict[str, Any]]:
    """
    Compares two OCI image metadata (config) files, specifically for required/important fields.

    Args:
        oci_image_path1, oci_image_path2: The path to the OCI image structured folder for each image.
        flags: types of issues to look for.

    Returns:
        List of differences between the metadata (config) files of each image.
    """

    metadata1 = oci.get_metadata(str(oci_image_path1))
    metadata2 = oci.get_metadata(str(oci_image_path2))

    import deepdiff
    diff = deepdiff.DeepDiff(metadata1, metadata2, view="tree")
    print(diff.pretty())
    import json
    print(diff.to_json())

    # Go over all flags and check those keys' values.
    diffs: list[MetadataDiff] = []
    for flag in flags:
        diff = _compare_full_key(metadata1, metadata2, flag.key)
        if diff:
            diffs.append(diff)

    return [asdict(diff) for diff in diffs]


def _compare_full_key(
    dict1: dict[str, Any],
    dict2: dict[str, Any],
    key: str,
) -> Optional[MetadataDiff]:
    """Compares two dicts and generates a list of differences in keys/value pairs."""

    # Valid OCI image spec keys need to have at most one level of nesting.
    if key.count(KEY_SEPARATOR) > 1:
        raise RuntimeError(f"Key is malformed: {key}")

    key_parts = key.split(KEY_SEPARATOR)
    if len(key_parts) > 1:
        parent_key = key_parts[0]
        child_key = key_parts[1]

        # Get subdicts and check they are valid.
        subdict1 = dict1.get(parent_key, {})
        subdict2 = dict2.get(parent_key, {})
        if not isinstance(subdict1, dict) or not isinstance(subdict2, dict):
            raise RuntimeError(
                f"Provided key {key} structured as nested, but subkeys {subdict1} or {subdict2} are not a dict."
            )

        return _compare_key(subdict1, subdict2, child_key, full_key=key)
    else:
        # Original key was not nested.
        return _compare_key(dict1, dict2, key, full_key=key)


def _compare_key(
    dict1: dict[str, Any], dict2: dict[str, Any], key: str, full_key: str
) -> Optional[MetadataDiff]:
    """
    Compares two dicts for the given key and generates a diff of the key/value pair,
    or None if both are not present, or are the same.

    Args:
        dict1, dict2: the two dicts where the key/value will be compared.
        key: the key to compare.
        full_key: the full path to the key we are comparing.

    Return:
        A MetaDiff indicating the difference, or None if no diff or not present.
    """
    # If key is in neither dict, there is no diff.
    if key not in dict1 and key not in dict2:
        return None

    value1 = dict1.get(key)
    value2 = dict2.get(key)

    # If key is in only one of the dicts, the diff is that value vs None.
    if key in dict1 and key not in dict2:
        return MetadataDiff(full_key, value1, None)

    if key in dict2 and key not in dict1:
        return MetadataDiff(full_key, None, value2)

    if value1 != value2:
        return MetadataDiff(full_key, value1, value2)

    # If we got here, keys are in both dicts, and either their values
    # are equal, or we are not comparing them, so no diff.
    return None
