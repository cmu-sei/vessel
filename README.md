# Vessel

Vessel is a project with the goal of promoting reproducible container builds. The first version of the Vessel tool has one command, `diff`, that compares two built container images and reports on differences between them, flagging as many known issues as possible. The goal of this command is to allow the detection of reproducibility issues when building container images, so that developers can take the appropriate measures to increase reproducibility.

## Setup

### Local Environment Setup

Pre-requisites:
* Linux OS - tested on Ubuntu 22.04
* Poetry
    * `curl -sSL https://install.python-poetry.org | python3 -`
    * Add to `~/.bashrc` (or equivalent profile): `export PATH=~/.local/bin:$PATH`

To set up the Python environment and the required packages:
1. `python -m venv .venv`
2. `poetry install --with extra_dependencies`

To set up additional external tools that are used:
* Install the skopeo package (e.g., `apt-get install skopeo`)
* Install the umoci package (e.g., `apt-get install umoci`)
* Install the diffoscope dependencies:
   * libmagic  (e.g., `apt-get install libmagic`)
   * libarchive-dev (e.g., `apt-get install ibarchive`)
   * Optional external compartors as needed (see https://pypi.org/project/diffoscope/)
      * Run `diffoscope --list-tools` for a full list. Also, the Dockerfile
      should install all of them.

Note that it is much simpler to run Vessel in a Docker container, which already contains all these dependencies. See [Docker Setup](#docker-setup).

### Docker Setup

Assuming you have Docker installed, run the following to build the vessel docker image.

* `docker build -t vessel .`

## Running

### In Local Environment
The tool can be run locally like this:

1. Make sure the environment is active: `source .venv/bin/activate`
2. Run `sudo env "PATH=$PATH" vessel diff`, with the proper arguments
   * This way of calling it avoids permission issues

Run `vessel --help` for full list of commands and options.

### Running the Docker container

* Note: Running within Docker avoids permission issues during the unpacking of the images.

To see commands and options:
* `docker run --rm vessel --help`
* `docker run --rm vessel diff --help`

Example running on two OCI tars:
* `docker run --rm -v INPUTDIR:/input -v OUTPUTDIR:/output vessel diff oci-archive:/input/image1.tar oci-archive:/input/image2.tar -o /output`

Example running on two images from Docker Hub:
* `docker run --rm -v $PWD/output:/output vessel diff docker://alpine:3.20.2 docker://alpine:3.20.2`

Example running on two images from a private Docker registry:
* `docker login [registry]`
* `docker run --rm -v $HOME/.docker/config.json:/root/.docker/config.json -v $PWD/output:/output vessel diff docker://[registry]/alpine docker://[registry]/alpine`

## Development

Follow the instructions at [Local Environment Setup](#local-environment-setup) first to set up your local environment.

To install the dev dependencies, run:
* `poetry install --with qa`

To lint the code, and check for format and type issues, execute:
* `make check`

To apply the safe lint fixes, and format fixes, execute:
* `make qa`

To run all checks and tests in a clean environment, similar to the Ci workflow, execute:
* `make ci`

### Building

To create a wheel, run: `poetry build`
