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

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any


@dataclass
class FailureSummary:
    """Represents a summary of failures in OCI image."""

    unknown_failures: int = 0
    """Number of failures that did not match a flag."""

    flagged_failures: int = 0
    """Number of failures that did match a flag."""

    trivial_failures: int = 0
    """Number of failures that matched a flag with a severity of as Low."""

    nontrivial_failures: int = 0
    """Number of failures that matched a flag with a severity different than Low."""

    total_failures: int = 0
    """Total number of failures found."""

    def to_dict(self) -> dict[str, Any]:
        """Returns this as a dictionary."""
        return asdict(self)

    def __init__(
        self,
        unknown_failure_count: int = 0,
        trivial_failure_count: int = 0,
        nontrivial_failure_count: int = 0,
    ):
        """Constructor, gets 3 independent values (unknown, trivial, nontrivial), aggregates the rest."""
        self.unknown_failures = unknown_failure_count
        self.trivial_failures = trivial_failure_count
        self.nontrivial_failures = nontrivial_failure_count

        # Calculate the two derived values.
        self.flagged_failures = (
            trivial_failure_count + nontrivial_failure_count
        )
        self.total_failures = (
            unknown_failure_count
            + trivial_failure_count
            + nontrivial_failure_count
        )
