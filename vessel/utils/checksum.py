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

"""Utility checksum functions."""

import hashlib
from logging import getLogger
from pathlib import Path
from typing import Any

import magic

logger = getLogger(__name__)


class FileHash:
    """Class to hold hash data for a file."""

    def __init__(
        self: "FileHash",
        path: str,
        filetype: str,
        hash: str,
    ) -> None:
        """FileHash constructor.

        Args:
            path: Path to file
            filetype: Type of file
            hash: sha256 hash of file
        """
        self.path = path
        self.filetype = filetype
        self.hash = hash


def hash_folder_contents(folder_path: Path) -> dict[str, FileHash]:
    """Calculate hash for each file within a path.

    Args:
        folder_path: Path to folder to hash all contents of

    Returns:
        Dict with filepaths as keys and FileHash object values with an
        entry for each file in folder_path
    """
    file_hashes: list[FileHash] = []

    for file_path in folder_path.rglob("*"):
        if not file_path.is_file():
            continue

        relative_path = file_path.relative_to(folder_path)
        hash = hashlib.sha256(file_path.read_bytes()).hexdigest()
        filetype = magic.from_file(str(file_path))
        file_hashes.append(FileHash(str(relative_path), filetype, hash))

    return {str(filehash.path): filehash for filehash in file_hashes}


def make_checksum_dict(
    path1: str,
    path2: str,
    path1_hash: str,
    path2_hash: str,
    filetype1: str,
    filetype2: str,
) -> dict[str, str]:
    """Return input data as a dict for summary output."""
    return {
        "path1": path1,
        "path2": path2,
        "path1_sha256": path1_hash,
        "path2_sha256": path2_hash,
        "filetype1": filetype1,
        "filetype2": filetype2,
    }


def summarize_checksums(
    diff_lookup: dict[tuple[str, str], list[dict[str, Any]]],
    folder_path1: Path,
    hashed_files1: dict[str, FileHash],
    folder_path2: Path,
    hashed_files2: dict[str, FileHash],
) -> dict:
    """Compares checkums of all files in two folder paths.

    Compares checksums of all files in two folder paths. Returns summary of the comparison
    with information about checksum matches and mismatches between files in each path, and
    files that are only in one of the two paths.

    Args:
        folder_path1: Path to first folder
        hashed_files1: Dict containing FileHash for each file in folder_path1 with filepath as key
        folder_path2: Path to second folder
        hashed_files2: Dict containing FileHash for each file in folder_path2 with filepath as key

    Dict summarizing:
        - image1, image2: the two image keys.
        - total_common_files: count of files present in both images.
        - checksum_mismatches: list of files present in both images but with different checksums.
        - checksum_matches: list of files present in both images with matching checksums.
        - only_in_image1: files only in image1.
        - only_in_image2: files only in image2.
    """
    only_in_image1 = sorted(
        set(hashed_files1.keys()) - set(hashed_files2.keys())
    )
    only_in_image2 = sorted(
        set(hashed_files2.keys()) - set(hashed_files1.keys())
    )
    common_files = sorted(
        set(hashed_files1.keys()) & set(hashed_files2.keys())
    )

    checksum_mismatches = []
    checksum_matches = []
    for path in common_files:
        if hashed_files1[path].hash != hashed_files2[path].hash:
            checksum_mismatches.append(
                make_checksum_dict(
                    path,
                    path,
                    hashed_files1[path].hash,
                    hashed_files2[path].hash,
                    hashed_files1[path].filetype,
                    hashed_files2[path].filetype,
                )
            )
        else:
            checksum_matches.append(
                make_checksum_dict(
                    path,
                    path,
                    hashed_files1[path].hash,
                    hashed_files2[path].hash,
                    hashed_files1[path].filetype,
                    hashed_files2[path].filetype,
                )
            )

    for key_tuple in diff_lookup:
        if key_tuple[0] != key_tuple[1]:
            only_in_image1 = list(set(only_in_image1) - set(key_tuple[0]))
            only_in_image2 = list(set(only_in_image2) - set(key_tuple[1]))

            if key_tuple[0] in hashed_files1 and key_tuple[1] in hashed_files2:
                common_files.extend([key_tuple[0], key_tuple[1]])
                common_files = sorted(common_files)

            if key_tuple[0] not in hashed_files1:
                logger.info(
                    f"{key_tuple[0]} found in diff list, but not in hashes."
                )
            elif key_tuple[1] not in hashed_files2:
                logger.info(
                    f"{key_tuple[1]} found in diff list, but not in hashes."
                )
            elif (
                hashed_files1[key_tuple[0]].hash != hashed_files2[key_tuple[1]]
            ):
                checksum_mismatches.append(
                    make_checksum_dict(
                        key_tuple[0],
                        key_tuple[1],
                        hashed_files1[path].hash,
                        hashed_files2[path].hash,
                        hashed_files1[path].filetype,
                        hashed_files2[path].filetype,
                    )
                )
            else:
                checksum_matches.append(
                    make_checksum_dict(
                        key_tuple[0],
                        key_tuple[1],
                        hashed_files1[path].hash,
                        hashed_files2[path].hash,
                        hashed_files1[path].filetype,
                        hashed_files2[path].filetype,
                    )
                )

    return {
        "image1": str(folder_path1),
        "image2": str(folder_path2),
        "total_common_files": len(common_files),
        "checksum_mismatches": checksum_mismatches,
        "checksum_matches": checksum_matches,
        "only_in_image1": only_in_image1,
        "only_in_image2": only_in_image2,
    }


def classify_checksum_mismatches(
    checksum_summary: dict[str, Any],
    diff_lookup: dict[tuple[str, str], list[dict[str, Any]]],
    hashed_files1: dict[str, FileHash],
    hashed_files2: dict[str, FileHash],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Classify each checksum mismatch as either trivial or nontrivial.

    Args:
        checksum_summary: Summary dict from summarize_checksums().
        diff_lookup: Dict mapping file pairs to diff result dicts.
        hashed_files1: Dict mapping filepaths to FileHash of that file for first folder
        hashed_files2: Dict mapping filepaths to FileHash of that file for second folder

    Returns:
        A tuple (trivial_diffs, nontrivial_diffs):
            - trivial_diffs: list of dicts for files with only trivial flagged failures.
            - nontrivial_diffs: list of dicts for files with unknown failures, non-metadata stat{} flagged failures.
    """
    trivial_diffs = []
    nontrivial_diffs = []
    for entry in checksum_summary.get("checksum_mismatches", []):
        key = (entry["path1"], entry["path2"])
        entry_diffs = diff_lookup.get(key, [])
        entry_flagged_failures = []
        entry_unknown_failures = []
        for diff in entry_diffs:
            flagged = diff.get("flagged_failures", [])
            unknowns = diff.get("unknown_failures", [])
            entry_flagged_failures.extend(flagged)
            entry_unknown_failures.extend(unknowns)

        types = []
        seen_types = set()
        for f in entry_flagged_failures:
            key2 = f"{f['id']}|{f['description']}"
            if key2 not in seen_types:
                types.append(key2)
                seen_types.add(key2)
        filetype1 = (
            hashed_files1[entry["path1"]].filetype
            if entry["path1"] in hashed_files1
            else None
        )
        filetype2 = (
            hashed_files2[entry["path2"]].filetype
            if entry["path2"] in hashed_files2
            else None
        )

        # If there are any unknown failures, classify as nontrivial
        if entry_unknown_failures:
            nontrivial_diffs.append(
                {
                    "files1": entry["path1"],
                    "files2": entry["path2"],
                    "flagged_failure_types": types,
                    "filetype1": filetype1,
                    "filetype2": filetype2,
                }
            )

        # If there are flagged failures (and no unknowns), trivial only if all flagged failures are severity Low and at least one nonmetadata
        elif entry_flagged_failures:
            all_trivial = all(
                failure.get("severity") == "Low"
                for failure in entry_flagged_failures
            )
            all_metadata = all(
                failure.get("metadata", False)
                for failure in entry_flagged_failures
            )
            # Only trivial, but all are metadata: treat as nontrivial/unknown
            if all_trivial and all_metadata:
                nontrivial_diffs.append(
                    {
                        "files1": entry["path1"],
                        "files2": entry["path2"],
                        "flagged_failure_types": types,
                        "filetype1": filetype1,
                        "filetype2": filetype2,
                    }
                )
            # Only trivial, and some are not metadata: treat as trivial
            elif all_trivial:
                trivial_diffs.append(
                    {
                        "files1": entry["path1"],
                        "files2": entry["path2"],
                        "flagged_failure_types": types,
                        "filetype1": filetype1,
                        "filetype2": filetype2,
                    }
                )
            # Otherwise, it's not all_trivial, append to non trivial
            else:
                nontrivial_diffs.append(
                    {
                        "files1": entry["path1"],
                        "files2": entry["path2"],
                        "flagged_failure_types": types,
                        "filetype1": filetype1,
                        "filetype2": filetype2,
                    }
                )
        # Otherwise, no flag and no unknown issue, non trivial
        else:
            nontrivial_diffs.append(
                {
                    "files1": entry["path1"],
                    "files2": entry["path2"],
                    "filetype1": filetype1,
                    "filetype2": filetype2,
                }
            )

    return trivial_diffs, nontrivial_diffs
