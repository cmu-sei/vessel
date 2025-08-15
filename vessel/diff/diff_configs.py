"""Compares two OCI config files for critical changes."""

from dataclasses import dataclass
from typing import Any, Optional

from vessel.utils import oci

# Critical keys to be compared.
ARCH_KEY = "architecture"
OS_KEY = "OS"
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


def compare_configs(
    unpacked_image_path1: str, unpacked_image_path2: str
) -> list[ConfigDiff]:
    """Compares two OCI config files, specifically for required/important fields."""

    config1 = oci.get_config(unpacked_image_path1)
    config2 = oci.get_config(unpacked_image_path2)

    # First check first-level critical configs, then inside the config field.
    diffs = compare_dict(config1, config2, [ARCH_KEY, OS_KEY])
    if CONFIG_KEY in config1 and CONFIG_KEY in config2:
        diffs.extend(
            compare_dict(
                config1[CONFIG_KEY],
                config2[CONFIG_KEY],
                CONFIG_SUBKEYS,
                CONFIG_KEY,
            )
        )

    return diffs


def compare_dict(
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
