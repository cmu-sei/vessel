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
from pathlib import Path
from typing import Any

import magic


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


def hash_folder_contents(folder_path: Path) -> list[FileHash]:
    """Calculate hash for each file within a path.

    Args:
        folder_path: Path to folder to hash all contents of

    Returns:
        List containing FileHash for each file in folder_path
    """
    file_hashes: list[FileHash] = []

    for file_path in folder_path.rglob("*"):
        if not file_path.is_file():
            continue

        relative_path = file_path.relative_to(folder_path)
        hash = hashlib.sha256(file_path.read_bytes()).hexdigest()
        filetype = magic.from_file(str(file_path))
        file_hashes.append(FileHash(str(relative_path), filetype, hash))

    return file_hashes


def summarize_checksums(
    folder_path1: Path,
    hashed_files1: list[FileHash],
    folder_path2: Path,
    hashed_files2: list[FileHash],
) -> dict:
    """Compares checkums of all files in two folder paths.

    Compares checksums of all files in two folder paths. Returns summary of the comparison
    with information about checksum matches and mismatches between files in each path, and
    files that are only in one of the two paths.

    Args:
        folder_path1: Path to first folder
        hashed_files1: List containing FileHash for each file in folder_path1
        folder_path2: Path to second folder
        hashed_files2: List containing FileHash for each file in folder_path2

    Dict summarizing:
        - image1, image2: the two image keys.
        - total_common_files: count of files present in both images.
        - checksum_mismatches: list of files present in both images but with different checksums.
        - checksum_matches: list of files present in both images with matching checksums.
        - only_in_image1: files only in image1.
        - only_in_image2: files only in image2.
    """
    files1 = {str(filehash.path): filehash for filehash in hashed_files1}
    files2 = {str(filehash.path): filehash for filehash in hashed_files2}

    only_in_image1 = sorted(set(files1.keys()) - set(files2.keys()))
    only_in_image2 = sorted(set(files2.keys()) - set(files1.keys()))
    common_files = sorted(set(files1.keys()) & set(files2.keys()))

    checksum_mismatches = []
    checksum_matches = []
    for f in common_files:
        if files1[f].hash != files2[f].hash:
            checksum_mismatches.append(
                {
                    "path": f,
                    "path1_sha256": files1[f].hash,
                    "path2_sha256": files2[f].hash,
                    "filetype1": files1[f].filetype,
                    "filetype2": files2[f].filetype,
                }
            )
        else:
            checksum_matches.append(
                {
                    "path": f,
                    "path1_sha256": files1[f].hash,
                    "path2_sha256": files2[f].hash,
                    "filetype1": files1[f].filetype,
                    "filetype2": files2[f].filetype,
                }
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
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Classify each checksum mismatch as either trivial or nontrivial.

    Args:
        checksum_summary: Summary dict from summarize_checksums().
        diff_lookup: Dict mapping file pairs to diff result dicts.

    Returns:
        A tuple (trivial_diffs, nontrivial_diffs):
            - trivial_diffs: list of dicts for files with only trivial flagged issues.
            - nontrivial_diffs: list of dicts for files with unknown issues, non-metadata stat{} flagged issues.
    """
    trivial_diffs = []
    nontrivial_diffs = []
    for entry in checksum_summary.get("checksum_mismatches", []):
        relative_path = entry["path"]
        key = (relative_path, relative_path)
        entry_diffs = diff_lookup.get(key, [])
        entry_flagged_issues = []
        entry_unknown_issues = []
        stat_has_nonmeta = False
        for diff in entry_diffs:
            flagged = diff.get("flagged_issues", [])
            unknowns = diff.get("unknown_issues", [])
            entry_flagged_issues.extend(flagged)
            entry_unknown_issues.extend(unknowns)

            # Only check stat {} flagged issues for non-metadata
            if diff.get("command", "") == "stat {}":
                for issue in flagged:
                    if not issue.get("metadata", False):
                        stat_has_nonmeta = True

        types = []
        seen_types = set()
        for f in entry_flagged_issues:
            key2 = f"{f['id']}|{f['description']}"
            if key2 not in seen_types:
                types.append(key2)
                seen_types.add(key2)

        # If there are any unknown issues, classify as nontrivial
        if entry_unknown_issues:
            nontrivial_diffs.append(
                {
                    "files1": relative_path,
                    "files2": relative_path,
                    "flagged_issue_types": types,
                }
            )
        # If any stat {} flagged issue has metadata == False, nontrivial
        elif stat_has_nonmeta:
            nontrivial_diffs.append(
                {
                    "files1": relative_path,
                    "files2": relative_path,
                    "flagged_issue_types": types,
                }
            )
        # If there are flagged issues (and no unknowns), trivial
        elif entry_flagged_issues:
            trivial_diffs.append(
                {
                    "files1": relative_path,
                    "files2": relative_path,
                    "flagged_issue_types": types,
                }
            )
        # Otherwise, nontrivial by default (For example: no flagged/unknown issues)
        else:
            nontrivial_diffs.append(
                {"files1": relative_path, "files2": relative_path}
            )

    return trivial_diffs, nontrivial_diffs
