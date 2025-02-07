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

"""Utility class for flags."""

import re


class Flag:
    """Class to hold represent a flag for a known issue."""

    def __init__(
        self: "Flag",
        flag_id: str,
        description: str,
        filepath: str,
        filetype: str,
        command: str,
        comment: str,
        indiff: str,
    ) -> None:
        """Initializer for Flag class."""
        self.flag_id = flag_id
        self.description = description

        self.regex_str: dict[str, str] = {}
        self.regex_str["filepath"] = filepath
        self.regex_str["filetype"] = filetype
        self.regex_str["command"] = command
        self.regex_str["comment"] = comment
        self.regex_str["indiff"] = indiff
        self.compile()

    def compile(self) -> None:
        """Compile regex strings and store them in self.regex."""
        self.regex = {
            key: re.compile(pattern) for key, pattern in self.regex_str.items()
        }
