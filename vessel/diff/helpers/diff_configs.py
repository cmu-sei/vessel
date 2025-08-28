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

"""Compares two OCI config files for critical changes."""

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional

from vessel.utils import oci

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
class ConfigDiff:
    """An entry describing a diff in a config file."""

    key: str
    parent_key: Optional[str]
    value1: Optional[Any]
    value2: Optional[Any]

    def to_dict(self) -> dict[str, Any]:
        """Returns diff object as a dict."""
        dict_obj: dict[str, Any] = {
            "config_key": self.key
            if not self.parent_key
            else f"{self.parent_key}/{self.key}",
            "value1": self.value1,
            "value2": self.value2,
        }
        return dict_obj


def compare_configs(
    oci_image_path1: Path, oci_image_path2: Path
) -> list[dict[str, Any]]:
    """
    Compares two OCI config files, specifically for required/important fields.

    Args:
        oci_image_path1, oci_image_path2: The path to the OCI image structured folder for each image.

    Returns:
        List of differences between the config files of each image.
    """

    config1 = oci.get_config(str(oci_image_path1))
    config2 = oci.get_config(str(oci_image_path2))

    # First check first-level critical configs, then inside the config field.
    diffs = _compare_dict(config1, config2, [ARCH_KEY, OS_KEY])

    # Now check inside the config field, or mark if either file does not have that field.
    if CONFIG_KEY in config1 and CONFIG_KEY in config2:
        diffs.extend(
            _compare_dict(
                config1[CONFIG_KEY],
                config2[CONFIG_KEY],
                CONFIG_SUBKEYS,
                CONFIG_KEY,
            )
        )
    elif CONFIG_KEY in config1 and CONFIG_KEY not in config2:
        diffs.append(ConfigDiff(CONFIG_KEY, None, config1[CONFIG_KEY], None))
    elif CONFIG_KEY in config2 and CONFIG_KEY not in config1:
        diffs.append(ConfigDiff(CONFIG_KEY, None, None, config2[CONFIG_KEY]))

    return [diff.to_dict() for diff in diffs]


def _compare_dict(
    dict1: dict[str, Any],
    dict2: dict[str, Any],
    keys: list[str],
    parent_key: Optional[str] = None,
) -> list[ConfigDiff]:
    """Compares two dicts and generates a list of differences in keys/value pairs."""
    diffs: list[ConfigDiff] = []

    for key in keys:
        if key in dict1 and key in dict2 and dict1[key] != dict2[key]:
            diffs.append(ConfigDiff(key, parent_key, dict1[key], dict2[key]))

        if key in dict1 and key not in dict2:
            diffs.append(ConfigDiff(key, parent_key, dict1[key], None))

        if key in dict2 and key not in dict1:
            diffs.append(ConfigDiff(key, parent_key, None, dict2[key]))

    return diffs
