#!/usr/bin/env bash
docker build -t vessel .
docker run --rm -v $PWD/input:/opt/project/input -v $PWD/output:/opt/project/output vessel diff -o ./output "$@"
