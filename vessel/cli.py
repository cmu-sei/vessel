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

"""Main module for the Vessel tool."""

import logging
import sys

import click

from vessel.diff import DiffCommand


@click.group()
@click.option(
    "-l",
    "--logging-level",
    type=click.Choice(
        [
            logging.getLevelName(logging.DEBUG),
            logging.getLevelName(logging.INFO),
            logging.getLevelName(logging.WARNING),
            logging.getLevelName(logging.ERROR),
            logging.getLevelName(logging.CRITICAL),
        ],
    ),
    default=logging.getLevelName(logging.INFO),
)
def vessel(logging_level: str) -> None:
    """Tool for creating reproducible container builds."""
    logging.basicConfig(level=logging_level)


@vessel.command()
@click.argument(
    "input_files",
    nargs=-1,
)
@click.option(
    "-c",
    "--compare-level",
    type=click.Choice(["image", "file"]),
    default="file",
    show_default=True,
    help=(
        "Diff mode selection: 'image' for image tar or file' for final image "
        "filesystem. Default 'file'"
    ),
)
@click.option(
    "-d",
    "--data-dir",
    type=click.Path(
        file_okay=False,
        readable=True,
        writable=True,
        resolve_path=True,
    ),
    help=(
        "Specify a data directory for unpacking the images. Default: Create a "
        "temporary directory that is auto-deleted."
    ),
)
@click.option(
    "-o",
    "--output-dir",
    type=click.Path(
        file_okay=False,
        readable=True,
        writable=True,
        resolve_path=True,
    ),
    help=(
        "Specify a output directory for diffoscope output. Default: Stores "
        "in current directory."
    ),
)
def diff(
    input_files: list[str],
    compare_level: str,
    data_dir: str,
    output_dir: str,
) -> None:
    """Unpack container images and compare differences with diffoscope.

    Compare IMAGES (OCI container images) byte by byte.
    """
    success: bool = DiffCommand(
        input_files,
        compare_level,
        data_dir,
        output_dir,
    ).execute()
    sys.exit(not success)
