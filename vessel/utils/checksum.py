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
    """
    
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
    """
    
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