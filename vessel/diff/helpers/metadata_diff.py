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

import typing
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Optional

from vessel.utils import oci

KEY_SEPARATOR = "/"
"""Separator used to show nested keys."""


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
    # Get data from both configs.
    metadata1 = oci.get_metadata(str(oci_image_path1))
    metadata2 = oci.get_metadata(str(oci_image_path2))

    diffs = _compare_dicts(metadata1, metadata2)

    return [asdict(diff) for diff in diffs]


def _compare_dicts(
    dict1: dict[str, Any], dict2: dict[str, Any]
) -> list[MetadataDiff]:
    """
    Compare dicts, which has to be done twice so we can find keys in the
    second that are not in the first one.
    """
    diffs: list[MetadataDiff] = []

    # Checked keys is needed to avoid comparing keys that are in both dicts twice.
    checked_keys: list[str] = []
    diffs.extend(
        _compare_dicts_ref(
            ref_dict=dict1,
            dict1=dict1,
            dict2=dict2,
            checked_keys=checked_keys,
        )
    )
    diffs.extend(
        _compare_dicts_ref(
            ref_dict=dict2,
            dict1=dict1,
            dict2=dict2,
            checked_keys=checked_keys,
        )
    )

    return diffs


def _compare_dicts_ref(
    ref_dict: dict[str, Any],
    dict1: dict[str, Any],
    dict2: dict[str, Any],
    checked_keys: list[str],
) -> list[MetadataDiff]:
    """
    Compares two dictionaries for differences.

    Args:
        ref_dict: one of the two dicts, used to get the keys to be compared.
        dict1, dict2: the two dictionaries to compare.
        checked_keys: list of keys already checked (to avoid comparing again between two dicts).
    Returns:
        List of MetaDiff differences between the dicts.
    """
    diffs: list[MetadataDiff] = []
    for key, value in ref_dict.items():
        # If key has already been checked, ignore; if not, add to list.
        if key in checked_keys:
            continue
        else:
            checked_keys.append(key)

        # Compare keys, but if it is a dict, delve into it.
        if isinstance(value, dict):
            subdict = typing.cast(dict[str, Any], value)
            for sub_key in subdict:
                # For each sub key in the dict, compare, remembering its parent.
                diff = _compare_full_key(dict1, dict2, sub_key, parent_key=key)
                if diff:
                    diffs.append(diff)
        else:
            # Compare values and existence directly, add if there are any diffs.
            diff = _compare_key(dict1, dict2, key)
            if diff:
                diffs.append(diff)
    return diffs


def _compare_full_key(
    dict1: dict[str, Any],
    dict2: dict[str, Any],
    key: str,
    parent_key: Optional[str] = None,
) -> Optional[MetadataDiff]:
    """
    Compares two dicts for a given key, which may include a nested path.

    Args:
        dict1, dict2: the two dicts where the key/value will be compared.
        key: the key to compare.
        parent_key: an optional key to the parent dict where the key/value pair will be.
    Return:
        A MetaDiff indicating the difference, or None if no diff or not present.
    """
    if parent_key:
        # Get subdicts and check they are valid.
        subdict1 = dict1.get(parent_key, {})
        subdict2 = dict2.get(parent_key, {})
        if not isinstance(subdict1, dict) or not isinstance(subdict2, dict):
            raise RuntimeError(
                f"Provided key {key} structured as nested, but subkeys {subdict1} or {subdict2} are not a dict."
            )
        return _compare_key(subdict1, subdict2, key, parent_key)
    else:
        # Original key was not nested.
        return _compare_key(dict1, dict2, key)


def _compare_key(
    dict1: dict[str, Any],
    dict2: dict[str, Any],
    key: str,
    parent_key: Optional[str] = None,
) -> Optional[MetadataDiff]:
    """
    Compares two dicts for the given key and generates a diff of the key/value pair,
    or None if both are not present, or are the same.

    Args:
        dict1, dict2: the two dicts where the key/value will be compared.
        key: the key to compare.
        parent_key: the parent key where the key is nested in, if any.
    Return:
        A MetaDiff indicating the difference, or None if no diff or not present.
    """
    # If key is in neither dict, there is no diff.
    if key not in dict1 and key not in dict2:
        return None

    value1 = dict1.get(key)
    value2 = dict2.get(key)

    # Build the full key for reference.
    full_key = f"{parent_key}{KEY_SEPARATOR}{key}" if parent_key else key

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
