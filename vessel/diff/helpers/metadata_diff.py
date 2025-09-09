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

from __future__ import annotations

import typing
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Optional

from vessel.diff.helpers.failure import FailureSummary
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

    matched_flag: Optional[MetadataFlag] = None
    """Flags that has been matched to this diff."""

    def to_dict(self) -> dict[str, Any]:
        """Returns this diff as a dictionary."""
        return asdict(self)


class MetadataDiffs:
    """Encapsulates a list of metadata diffs."""

    def __init__(self, diffs: list[MetadataDiff] = []):
        "Constructor."
        self.diffs = diffs
        """List of diffs in OCI image metadata/config."""

    def to_dict_list(self) -> list[dict[str, Any]]:
        """Returns this diff as a list of dictionaries."""
        return [diff.to_dict() for diff in self.diffs]


@dataclass
class MetadataFlag:
    """Represents a type of issue, and the key it is being associated to."""

    category_id: str
    """The id of the category this flag is covering."""

    key: str
    """The full path to the key with the diff."""

    severity: str
    """The severity being used to treat this case."""

    def to_dict(self) -> dict[str, Any]:
        """Returns this as a dictionary."""
        return asdict(self)


def compare_metadata(
    oci_image_path1: Path, oci_image_path2: Path
) -> MetadataDiffs:
    """
    Compares two OCI image metadata (config) files, specifically for required/important fields.

    Args:
        oci_image_path1, oci_image_path2: The path to the OCI image structured folder for each image.

    Returns:
        List of differences between the metadata (config) files of each image.
    """
    metadata1 = oci.get_metadata(str(oci_image_path1))
    metadata2 = oci.get_metadata(str(oci_image_path2))
    return MetadataDiffs(_compare_dicts(metadata1, metadata2))


def load_flags(flags_config: list[dict[str, Any]]) -> list[MetadataFlag]:
    """Loads metadata flags from a loaded config."""
    flags: list[MetadataFlag] = []
    for flag_info in flags_config:
        flag = MetadataFlag(
            category_id=flag_info["id"],
            key=flag_info["key"],
            severity=flag_info["severity"],
        )
        flags.append(flag)
    return flags


def match_flags(
    diff_list: MetadataDiffs, flags: list[MetadataFlag]
) -> tuple[MetadataDiffs, FailureSummary]:
    """
    Matches flags to the given diffs, and returns update diffs with flags, as well as a match summary.

    Args:
        diffs: list of diffs to match with the flags.
        flags: types of issues to look for, to be matched on the diffs.

    Returns:
        List of differences updated with their matched flags, as well as a summary of matches.
    """
    # Go over all diffs, and for each one, if a flag has a matching key, mark that flag in that diff.
    for diff in diff_list.diffs:
        for flag in flags:
            if diff.key == flag.key:
                diff.matched_flag = flag

    # Create summary of diffs.
    summary = FailureSummary()
    for diff in diff_list.diffs:
        if not diff.matched_flag:
            summary.unknown_failures += 1
        else:
            if diff.matched_flag.severity == "Low":
                summary.trivial_failures += 1
            else:
                summary.nontrivial_failures += 1
    summary.calculate_aggregated_values()

    return diff_list, summary


def _compare_dicts(
    dict1: dict[str, Any], dict2: dict[str, Any]
) -> list[MetadataDiff]:
    """
    Compare dicts for differences.

    Args:
        dict1, dict2: the two dictionaries to compare.
    Returns:
        List of MetaDiff differences between the dicts.
    """
    # First we need to combine the keys of both dicts so we can ensure we check for keys that are in both dicts.
    key_dict = _combine_dict_keys(dict1, dict2)

    # Now we go over all keys, and make the diffs.
    diffs: list[MetadataDiff] = []
    for key, value in key_dict.items():
        # Compare keys, but if it is a dict, delve into it.
        if len(value) > 0:
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


def _combine_dict_keys(
    dict1: dict[str, Any], dict2: dict[str, Any]
) -> dict[str, dict[str, bool]]:
    """Combines the keys of two dicts, into another one. Does so recursively into on nested level."""
    combined: dict[str, dict[str, bool]] = {}

    for curr_dict in [dict1, dict2]:
        for key, value in curr_dict.items():
            if key not in combined:
                combined[key] = {}
            if isinstance(value, dict):
                for subkey in value.keys():
                    if subkey not in combined[key]:
                        combined[key][subkey] = True

    return combined


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
