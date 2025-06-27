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

def get_all_files_with_sha256(unpacked_path: Path) -> list[dict[str, str]]:
    """Recursively collect all files under rootfs/ in the given directory and compute their SHA-256 checksums.

    Args:
        unpacked_path: Path to the directory containing a rootfs/ subdirectory.

    Returns:
        List of dictionaries with path and sha256 fields for each file found.
    """
    file_hashes = []
    unpacked_rootfs_path = unpacked_path / "rootfs"

    for path in unpacked_rootfs_path.rglob("*"):
        if not path.is_file():
            continue

        relative_path = path.relative_to(unpacked_rootfs_path)
        sha = hashlib.sha256(path.read_bytes()).hexdigest()
        file_hashes.append({"path": f"rootfs/{relative_path}", "sha256": sha})

    return file_hashes


def summarize_checksums(file_records: dict[str, list[dict[str, str]]]) -> dict:
    """Compare the SHA-256 checksums of files from two images and summarize the results.

    Args:
        file_records: Dict mapping image paths to lists of file checksum dicts.

    Returns:
        Dict summarizing:
            - image1, image2: the two image keys.
            - total_common_files: count of files present in both images.
            - checksum_mismatches: list of files present in both images but with different checksums.
            - checksum_matches: list of files present in both images with matching checksums.
            - only_in_image1: files only in image1.
            - only_in_image2: files only in image2.
    """
    [path1, path2] = list(file_records.keys())
    files1 = {entry["path"]: entry["sha256"] for entry in file_records[path1]}
    files2 = {entry["path"]: entry["sha256"] for entry in file_records[path2]}

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
        "image1": path1,
        "image2": path2,
        "total_common_files": len(common_files),
        "checksum_mismatches": checksum_diff,
        "checksum_matches": checksum_matches,
        "only_in_image1": only_in_image1,
        "only_in_image2": only_in_image2,
    }


def get_sha256(path: str) -> str:
    """Compute the SHA-256 checksum of the given file.

    Args:
        path: Path to the file.

    Returns:
        SHA-256 checksum as a hex string.
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
        rel = entry["path"]
        key = (rel, rel)
        diffs = diff_lookup.get(key, [])
        all_flagged = []
        all_unknown = []
        stat_has_nonmeta = False
        for d in diffs:
            flagged = d.get("flagged_issues", [])
            unknowns = d.get("unknown_issues", [])
            all_flagged.extend(flagged)
            all_unknown.extend(unknowns)

            # Only check stat {} flagged issues for non-metadata
            if d.get("command", "") == "stat {}":
                for issue in flagged:
                    if not issue.get("metadata", False):
                        stat_has_nonmeta = True

        types = []
        seen_types = set()
        for f in all_flagged:
            key2 = f"{f['id']}|{f['description']}"
            if key2 not in seen_types:
                types.append(key2)
                seen_types.add(key2)

        # If there are any unknown issues, classify as nontrivial
        if all_unknown:
            nontrivial_diffs.append({
                "files1": rel,
                "files2": rel,
                "flagged_issue_types": types
            })
        # If any stat {} flagged issue has metadata == False, nontrivial
        elif stat_has_nonmeta:
            nontrivial_diffs.append({
                "files1": rel,
                "files2": rel,
                "flagged_issue_types": types
            })
        # If there are flagged issues (and no unknowns), trivial
        elif all_flagged:
            trivial_diffs.append({
                "files1": rel,
                "files2": rel,
                "flagged_issue_types": types
            })
        # Otherwise, nontrivial by default (For example: no flagged/unknown issues)
        else:
            nontrivial_diffs.append({
                "files1": rel,
                "files2": rel
            })

    return trivial_diffs, nontrivial_diffs