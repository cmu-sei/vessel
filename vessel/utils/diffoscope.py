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

"""Utility Diffoscope functions."""

import re
from pathlib import Path

import magic
import subprocess
import hashlib
from logging import getLogger
logger = getLogger(__name__)

from vessel.utils.flag import Flag
from vessel.utils.unified_diff import (
    Diff,
    intervals_to_str,
    issues_from_difflines,
    make_issue_dict,
)

from typing import List, Dict, Any, Tuple

def is_binary(file_path: Path) -> bool:
    try:
        result = subprocess.run(
            ["file", str(file_path)],
            capture_output=True, text=True
        )
        return "ELF" in result.stdout or "executable" in result.stdout or "shared object" in result.stdout
    except Exception:
        return False

def build_diffoscope_command(
    output_dir_path: str,
    output_file_name: str,
    path1: str,
    path2: str,
    compare_level: str,
) -> list[str]:
    """Generates a command list to execute diffoscope.

    Args:
        output_dir_path: Path to directory that Diffoscope json output will be
            written to
        output_file_name: File name that will be used for diffoscope output
        path1: The first path to compare
        path2: The second path to compare
        compare_level: Diff mode (image or file)

    Returns:
        Commands list to execute diffoscope.
    """
    cmd = ["diffoscope"]
    cmd.extend(["--json", f"{output_dir_path}/{output_file_name}"])

    if compare_level == "file":
        cmd.append("--new-file")
    logger.info("Hello starting to diff now")

    cmd.extend([path1, path2])
    cmd.extend(["--exclude-directory-metadata", "no"])
    exclude_patterns = [
        r'^readelf.*',
        r'^objdump.*',
        r'^strings.*',
        r'^xxd.*',
    ]

    for pattern in exclude_patterns:
        cmd.extend(["--exclude-command", pattern])
    cmd.extend(["--profile", f"{output_dir_path}/profile.txt"])
    return cmd

def get_all_files_with_sha256(root: Path) -> list[dict[str, str]]:
    all_files = []
    rootfs = root / "rootfs"

    for path in rootfs.rglob("*"):
        if not path.is_file():
            continue

        rel_path = path.relative_to(rootfs)
        rel_parts = rel_path.parts

        sha = hashlib.sha256(path.read_bytes()).hexdigest()
        all_files.append({
            "path": f"rootfs/{rel_path}",
            "sha256": sha
        })

    return all_files

def summarize_checksums(file_records: dict[str, list[dict[str, str]]]) -> dict:
    [path1, path2] = list(file_records.keys())
    files1 = {entry["path"]: entry["sha256"] for entry in file_records[path1]}
    files2 = {entry["path"]: entry["sha256"] for entry in file_records[path2]}

    only_in_path1 = sorted(set(files1.keys()) - set(files2.keys()))
    only_in_path2 = sorted(set(files2.keys()) - set(files1.keys()))
    common_files = sorted(set(files1.keys()) & set(files2.keys()))

    checksum_diff = []
    for f in common_files:
        if files1[f] != files2[f]:
            checksum_diff.append({
                "path": f,
                "path1_sha256": files1[f],
                "path2_sha256": files2[f]
            })
    checksum_matches = []
    for f in common_files:
        if files1[f] == files2[f]:
            checksum_matches.append({
                "path": f,
                "path1_sha256": files1[f],
                "path2_sha256": files2[f]
            })

    return {
        "path1": path1,
        "path2": path2,
        "total_common_files": len(common_files),
        "checksum_mismatches": checksum_diff,
        "checksum_matches": checksum_matches,
        "only_in_path1": only_in_path1,
        "only_in_path2": only_in_path2
    }

def get_sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()

def build_diff_lookup(diff_list: List[Dict[str, Any]]) -> Dict[Tuple[str, str], List[Dict[str, Any]]]:
    lookup = {}
    for d in diff_list:
        def rel_after_rootfs(path):
            idx = path.find("rootfs/")
            return path[idx:] if idx != -1 else path

        rel1 = rel_after_rootfs(d["source1"])
        rel2 = rel_after_rootfs(d["source2"])
        for key in [(rel1, rel2), (rel2, rel1)]:
            if key not in lookup:
                lookup[key] = []
            lookup[key].append(d)
    return lookup

def classify_checksum_mismatches(
    checksum_summary: Dict[str, Any],
    diff_lookup: Dict[Tuple[str, str], List[Dict[str, Any]]],
    path1: str,
    path2: str
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    trivial_diffs = []
    nontrivial_diffs = []
    for entry in checksum_summary.get("checksum_mismatches", []):
        rel = entry["path"]
        file1_full = str(Path(path1) / rel)
        file2_full = str(Path(path2) / rel)
        key = (rel, rel)
        diffs = diff_lookup.get(key, [])
        if not diffs:
            nontrivial_diffs.append({
                "files1": file1_full,
                "files2": file2_full
            })
            continue
        all_flagged = []
        all_unknown = []
        for d in diffs:
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
            trivial_diffs.append({
                "files1": file1_full,
                "files2": file2_full,
                "flagged_issue_types": types
            })
        else:
            nontrivial_diffs.append({
                "files1": file1_full,
                "files2": file2_full
            })
    return trivial_diffs, nontrivial_diffs

def parse_diffoscope_output(
    current_detail: dict,
    flags: list[Flag],
    parent_source1: str = "",
    parent_source2: str = "",
    parent_comments: list[str] | None = None,
    files_summary: list[dict] | None = None,
    file_checksum: bool = False,
) -> tuple[int, int, list, list[dict]]:
    """Recursively parses diffoscope json output.

    Recursively navigates through entirety of diffoscope json output
    parsing the diffs and returning a JSON object with issues
    flagged based on contents of `config/diff_config.yaml`

    Args:
        current_detail: Dict object containing an instance of a diff
                        from diffoscope output.
        flags: List of all flags contained within
                `config/diff_config.yaml`
        parent_source1: Source of diff of parent1 to substitute into
                        source field if the source is a CLI tool and
                        not a file name
        parent_source2: Source of diff of parent2 to substitute into
                        source field if the source is a CLI tool and
                        not a file name
        parent_comments: List of comments from the parent object in diffoscope
                        as sometimes the comments that relate to a child are in
                        the parent detail

    Returns:
        Count of unknown issues, count of flagged issues, diff list,
        and overall file summary.
    """
    flagged_issues_count = 0
    unknown_issues_count = 0
    diff_list = []

    if files_summary is None:
        files_summary = []

    if current_detail["unified_diff"] is not None:
        temp_comments = []
        if "comments" in current_detail:
            temp_comments.extend(current_detail["comments"])
        if parent_comments:
            temp_comments.extend(parent_comments)

        diff = Diff(
            current_detail["source1"],
            current_detail["source2"],
            parent_source1,
            parent_source2,
            temp_comments,
            current_detail["unified_diff"],
        )
        # Handles case where diff is found with a command such as stat {}.
        # Diffoscope lists the source of the diff as the command that it used to get
        # the diff, so the file path must be grabbed from the parent.
        if (
            not Path(diff.source1).is_file()
            and not Path(diff.source2).is_file()
        ):
            diff.command = current_detail["source1"]
            diff.source1 = parent_source1
            diff.source2 = parent_source2

        files_summary.append({
            "source1": diff.source1,
            "source2": diff.source2,
            "sha256_source1": get_sha256(diff.source1) if Path(diff.source1).is_file() else None,
            "sha256_source2": get_sha256(diff.source2) if Path(diff.source2).is_file() else None,
            "flagged": 0,
            "unknown": 0,
        })

        file_entry = files_summary[-1]
        # Initialize to False to ensure one iteration through the flags.
        # If it then is found to be binary, the rest of the lines
        # will not be evaluated to not check binary line by line.
        is_binary = False
        for minus_line, plus_line in zip(
            diff.minus_aligned_lines,
            diff.plus_aligned_lines,
            strict=False,
        ):
            is_binary = bool(current_detail.get("has_internal_linenos"))
            for flag in flags:
                flag_matches = True
                file_type_1 = ""
                file_type_2 = ""
                # Check if filepath matches flag
                if not flag.regex["filepath"].search(
                    diff.source1,
                ) or not flag.regex["filepath"].search(
                    diff.source2,
                ):
                    flag_matches = False

                # Check if filetype matches flag
                if (
                    flag_matches
                    and Path(diff.source1).is_file()
                    and Path(diff.source2).is_file()
                ):
                    file_type_1 = magic.from_file(
                        diff.source1,
                    )
                    file_type_2 = magic.from_file(
                        diff.source2,
                    )

                    if not flag.regex["filetype"].search(
                        file_type_1,
                    ) or not flag.regex["filetype"].search(file_type_2):
                        flag_matches = False

                # Check if command matches flag
                if flag_matches and (
                    (
                        diff.command != ""
                        and not flag.regex["command"].search(diff.command)
                    )
                    or (
                        diff.command == ""
                        and flag.regex["command"] != re.compile(".")
                    )
                ):
                    flag_matches = False

                # Check if comment matches flag
                if flag_matches and (
                    (
                        diff.comments != []
                        and not any(
                            flag.regex["comment"].search(comment) 
                            for comment in diff.comments
                        )
                    )
                    or (
                        diff.comments == []
                        and flag.regex["comment"] != re.compile(".")
                    )
                ):  # fmt: skip
                    flag_matches = False

                # Handle a binary line that matches the flag
                if (
                    flag_matches
                    and is_binary
                    and flag.regex["indiff"] == re.compile(".*")
                ):
                    flagged_issues_count += 1
                    file_entry["flagged"] += 1
                    diff.flagged_issues.append(
                        {
                            "id": flag.flag_id,
                            "description": flag.description,
                            "comments": [
                                "Flag indiff regex are not ran on binary "
                                "unified diff. However this matched all "
                                "of the other criteria for this flag. and "
                                "indiff was set to '.*'",
                            ],
                        },
                    )

                # Handle any non-binary line that matches the flag
                elif flag_matches:
                    (
                        flagged_issue_list,
                        unknown_issue_list,
                        minus_line.unmatched_intervals,
                        plus_line.unmatched_intervals,
                    ) = issues_from_difflines(
                        minus_line,
                        plus_line,
                        flag,
                    )
                    # Check to not create duplicate matches on flags that match based on filepath, filetype, command or comment 
                    #     and have indiff set to ".*"
                    if flag.regex["indiff"] != re.compile(".*") or flag.flag_id not in [flag["id"] for flag in diff.flagged_issues]:
                        flagged_issues_count += len(flagged_issue_list)
                        unknown_issues_count += len(unknown_issue_list)
                        file_entry["flagged"] += len(flagged_issue_list)
                        file_entry["unknown"] += len(unknown_issue_list)
                        diff.flagged_issues.extend(flagged_issue_list)
                        diff.unknown_issues.extend(unknown_issue_list)

            # Check so line by line comparison don't happen in binary diffs and
            # this is after all the flags have been checked so the diff is done
            # being evaluated
            if is_binary:
                if len(diff.flagged_issues) == 0:
                    unknown_issues_count += 1
                    file_entry["unknown"] += 1
                    diff.unknown_issues.append(
                        {
                            "comments": [
                                "Flag indiff regex are not ran on binary "
                                "unified diff. This file did not match any "
                                "flags.",
                            ],
                        },
                    )

                break

            minus_unmatched_str = (
                intervals_to_str(
                    minus_line.text,
                    minus_line.unmatched_intervals,
                )
                if minus_line
                else None
            )
            plus_unmatched_str = (
                intervals_to_str(
                    plus_line.text,
                    plus_line.unmatched_intervals,
                )
                if plus_line
                else None
            )
            if minus_unmatched_str != plus_unmatched_str:
                unknown_issues_count += 1
                file_entry["unknown"] += 1
                diff.unknown_issues.append(
                    make_issue_dict(
                        minus_line if minus_line else None,
                        plus_line if plus_line else None,
                        minus_unmatched_str,
                        plus_unmatched_str,
                    ),
                )

        diff_list.append(diff.to_slim_dict())

    # Recurvisely navigating through the tree
    if "details" in current_detail:
        for child in current_detail["details"]:
            child_return = parse_diffoscope_output(
                child,
                flags,
                current_detail["source1"],
                current_detail["source2"],
                current_detail.get("comments"),
                files_summary,
                file_checksum=file_checksum,
            )
            unknown_issues_count += child_return[0]
            flagged_issues_count += child_return[1]
            diff_list.extend(child_return[2])

    # Only generate the final summary when it's top-level call (end of recursion)
    if parent_source1 == "" and parent_source2 == "" and parent_comments is None:
        rootfs1 = Path(current_detail["source1"]).parent
        rootfs2 = Path(current_detail["source2"]).parent

        all_source1_files = get_all_files_with_sha256(rootfs1)
        all_source2_files = get_all_files_with_sha256(rootfs2)

        file_records = {
            str(rootfs1): all_source1_files,
            str(rootfs2): all_source2_files,
        }

        checksum_summary = summarize_checksums(file_records)
        diff_lookup = build_diff_lookup(diff_list)
        path1 = checksum_summary.get("path1")
        path2 = checksum_summary.get("path2")

        trivial_diffs, nontrivial_diffs = classify_checksum_mismatches(
            checksum_summary, diff_lookup, path1, path2
        )

        files_summary = {
            "file_comparisons": checksum_summary,
            str(rootfs1): {
                "file_count": len(all_source1_files),
                "files": all_source1_files,
            },
            str(rootfs2): {
                "file_count": len(all_source2_files),
                "files": all_source2_files,
            },
        }

        files_summary["file_comparisons"]["trivial_checksum_different_files"] = trivial_diffs
        files_summary["file_comparisons"]["nontrivial_checksum_different_files"] = nontrivial_diffs

        return unknown_issues_count, flagged_issues_count, diff_list, files_summary
    return unknown_issues_count, flagged_issues_count, diff_list, files_summary
