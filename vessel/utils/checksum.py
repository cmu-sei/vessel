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


class FileHash:
    """Class to hold hash data for a file."""
    def __init__(
        self: "FileHash",
        path: str,
        hash: str,
    ) -> None:
        """FileHash constructor.
        
        Args:
            path: Path to file
            hash: sha256 hash of file
        """
        self.path = path
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
        file_hashes.append(FileHash(str(relative_path), hash))

    return file_hashes


def summarize_checksums(folder_path1: Path, hashed_files1: list[FileHash], folder_path2: Path, hashed_files2: list[FileHash]) -> dict:
    """Compares checkums of all files in two folder paths.

    Compares checksums of all files in two folder paths. Returns summary of the comparison
    with information about checksum matches and mismatches between files in each path, and
    files that are only in one of the two paths.

    Args:
        folder_path1: Path to first folder
        hashed_files1: List containing FileHash for each file in folder_path1
        folder_path2: Path to second folder
        hashed_files2: List containing FileHash for each file in folder_path2
    
    Returns:
        Summary of the comparison in dict format.
    """
    files1 = {str(filehash.path): filehash.hash for filehash in hashed_files1}
    files2 = {str(filehash.path): filehash.hash for filehash in hashed_files2}

    only_in_image1 = sorted(set(files1.keys()) - set(files2.keys()))
    only_in_image2 = sorted(set(files2.keys()) - set(files1.keys()))
    common_files = sorted(set(files1.keys()) & set(files2.keys()))

    checksum_diff = []
    for f in common_files:
        if files1[f] != files2[f]:
            checksum_diff.append(
                {
                    "path": f,
                    "path1_sha256": files1[f],
                    "path2_sha256": files2[f],
                }
            )
    checksum_matches = []
    for f in common_files:
        if files1[f] == files2[f]:
            checksum_matches.append(
                {
                    "path": f,
                    "path1_sha256": files1[f],
                    "path2_sha256": files2[f],
                }
            )

    return {
        "image1": str(folder_path1),
        "image2": str(folder_path2),
        "total_common_files": len(common_files),
        "checksum_mismatches": checksum_diff,
        "checksum_matches": checksum_matches,
        "only_in_image1": only_in_image1,
        "only_in_image2": only_in_image2,
    }


def get_sha256(path: str) -> str:
    """
    
    """
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def classify_checksum_mismatches(
    checksum_summary: dict[str, Any],
    diff_lookup: dict[tuple[str, str], list[dict[str, Any]]],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """
    
    """
    trivial_diffs = []
    nontrivial_diffs = []
    for entry in checksum_summary.get("checksum_mismatches", []):
        rel = entry["path"]
        key = (rel, rel)
        diffs = diff_lookup.get(key, [])
        if not diffs:
            nontrivial_diffs.append({"files1": rel, "files2": rel})
            continue
        all_flagged = []
        all_unknown = []
        for d in diffs:
            # Ignore flagged issues if this is just stat {} output
            if d.get("command", "") == "stat {}":
                continue
            all_flagged.extend(d.get("flagged_issues", []))
            all_unknown.extend(d.get("unknown_issues", []))
        if all_flagged and not all_unknown:
            types = []
            seen_types = set()
            for f in all_flagged:
                key2 = f"{f['id']}|{f['description']}"
                if key2 not in seen_types:
                    types.append(key2)
                    seen_types.add(key2)
            trivial_diffs.append(
                {"files1": rel, "files2": rel, "flagged_issue_types": types}
            )
        else:
            nontrivial_diffs.append({"files1": rel, "files2": rel})
    return trivial_diffs, nontrivial_diffs