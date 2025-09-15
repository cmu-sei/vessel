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
import json
from logging import getLogger
from pathlib import Path
from typing import Any, Optional

import magic

from vessel.utils.diffoscope import build_diff_lookup

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

    def to_dict(self) -> dict[str, str]:
        """Serialize FileHash to dict"""
        return {
            "filetype": self.filetype,
            "hash": self.hash,
        }

    @staticmethod
    def from_dict(path: str, dictionary: dict[str, str]) -> "FileHash":
        """
        Deserialize a FileHash object from a dictionary.

        Args:
            path (str): The path of the file (used as the key in the metadata dict).
            dictionary (dict): Dictionary with keys 'filetype' and 'hash'.

        Returns:
            FileHash: New FileHash object created from the dictionary.
        """
        return FileHash(
            path=path, filetype=dictionary["filetype"], hash=dictionary["hash"]
        )


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


def write_checksum_metadata(
    path, hashed_files1, hashed_files2, image1_path=None, image2_path=None
):
    data = {
        "image1_path": str(image1_path) if image1_path is not None else "",
        "image2_path": str(image2_path) if image2_path is not None else "",
        "hashed_files1": {k: v.to_dict() for k, v in hashed_files1.items()},
        "hashed_files2": {k: v.to_dict() for k, v in hashed_files2.items()},
    }
    with open(path, "w") as f:
        json.dump(data, f, indent=2)


def load_checksum_metadata(path):
    with open(path, "r") as f:
        data = json.load(f)
    hashed_files1 = {
        k: FileHash.from_dict(k, v) for k, v in data["hashed_files1"].items()
    }
    hashed_files2 = {
        k: FileHash.from_dict(k, v) for k, v in data["hashed_files2"].items()
    }
    image1 = data.get("image1_path", "")
    image2 = data.get("image2_path", "")
    return hashed_files1, hashed_files2, image1, image2


def summarize_checksums(
    diff_lookup: dict[tuple[str, str], list[dict[str, Any]]],
    folder_path1: Path,
    hashed_files1: dict[str, FileHash],
    folder_path2: Path,
    hashed_files2: dict[str, FileHash],
) -> dict[str, Any]:
    """Compares checkums of all files in two folder paths.

    Compares checksums of all files in two folder paths. Returns summary of the comparison
    with information about checksum matches and mismatches between files in each path, and
    files that are only in one of the two paths.

    Args:
        diff_lookup: Dict mapping file pairs to diff result dicts.
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

    for path1, path2 in diff_lookup:
        if path1 != path2:
            if path1 in only_in_image1 and path2 in only_in_image2:
                only_in_image1 = list(set(only_in_image1) - {path1})
                only_in_image2 = list(set(only_in_image2) - {path2})
                common_files.append(
                    f"{path1} <-> {path2}"
                )  # append the file pair so the common files don't get inflated
                common_files = sorted(set(common_files))

            if path1 not in hashed_files1:
                logger.info(f"{path1} found in diff list, but not in hashes.")
                continue
            if path2 not in hashed_files2:
                logger.info(f"{path2} found in diff list, but not in hashes.")
                continue

            if hashed_files1[path1].hash != hashed_files2[path2].hash:
                checksum_mismatches.append(
                    make_checksum_dict(
                        path1,
                        path2,
                        hashed_files1[path1].hash,
                        hashed_files2[path2].hash,
                        hashed_files1[path1].filetype,
                        hashed_files2[path2].filetype,
                    )
                )
            else:
                checksum_matches.append(
                    make_checksum_dict(
                        path1,
                        path2,
                        hashed_files1[path1].hash,
                        hashed_files2[path2].hash,
                        hashed_files1[path1].filetype,
                        hashed_files2[path2].filetype,
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
                    "flagged_failure_types": types,
                    "filetype1": filetype1,
                    "filetype2": filetype2,
                }
            )

    return trivial_diffs, nontrivial_diffs


def generate_filesummary_and_checksum(
    diff_list: list[dict],
    rootfs_path1: Optional[Path] = None,
    rootfs_path2: Optional[Path] = None,
    hashed_files1: Optional[dict[str, "FileHash"]] = None,
    hashed_files2: Optional[dict[str, "FileHash"]] = None,
    image1_path: Optional[str] = None,
    image2_path: Optional[str] = None,
) -> tuple[list[dict], dict]:
    """Generate file summary and checksum summary

    Build diff_lookup table from the diff results and compute
    checksums and file differences between two image rootfs directories or
    two precomputed hashed_files dictionaries

    Args:
        diff_list: diffs from parsed diffoscope output.
        rootfs_path1: (Optional) Path to first image rootfs.
        rootfs_path2: (Optional) Path to second image rootfs.
        hashed_files1: (Optional) Precomputed hashes for files in rootfs_path1.
        hashed_files2: (Optional) Precomputed hashes for files in rootfs_path2.
        image1: (Optional) image1 full path loaded from metadata.
        image2: (Optional) image2 full path loaded from metadata.

    Returns:
        files_summary: List containing file and checksum comparison details.
        checksum_summary: Dict summarizing checksum matches, mismatches, and unique files.
    """
    # If hashes not supplied, compute them from rootfs
    if hashed_files1 is None:
        if rootfs_path1 is None:
            raise ValueError(
                "rootfs_path1 cannot be None when hashed_files1 is not provided"
            )
        hashed_files1 = hash_folder_contents(rootfs_path1)
    if hashed_files2 is None:
        if rootfs_path2 is None:
            raise ValueError(
                "rootfs_path2 cannot be None when hashed_files2 is not provided"
            )
        hashed_files2 = hash_folder_contents(rootfs_path2)

    # Make sure image1_path and image2_path were loaded from the metadata file as well
    if rootfs_path1 is not None and rootfs_path2 is not None:
        image1_path = str(rootfs_path1)
        image2_path = str(rootfs_path2)
    elif image1_path is not None and image2_path is not None:
        image1_path = image1_path
        image2_path = image2_path
    else:
        raise ValueError(
            "When passing precomputed hashes, image1 path and image2 path must be provided"
        )

    diff_lookup = build_diff_lookup(diff_list)
    if rootfs_path1 is None or rootfs_path2 is None:
        checksum_summary = summarize_checksums(
            diff_lookup,
            Path(image1_path),
            hashed_files1,
            Path(image2_path),
            hashed_files2,
        )
    else:
        checksum_summary = summarize_checksums(
            diff_lookup,
            rootfs_path1,
            hashed_files1,
            rootfs_path2,
            hashed_files2,
        )

    trivial_diffs, nontrivial_diffs = classify_checksum_mismatches(
        checksum_summary, diff_lookup, hashed_files1, hashed_files2
    )
    files_summary = [
        {
            "image1": checksum_summary["image1"],
            "image2": checksum_summary["image2"],
            "only_in_image1": checksum_summary["only_in_image1"],
            "only_in_image2": checksum_summary["only_in_image2"],
            "trivial_checksum_different_files": trivial_diffs,
            "nontrivial_checksum_different_files": nontrivial_diffs,
        }
    ]
    return files_summary, checksum_summary
