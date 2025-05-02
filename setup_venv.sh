#!/usr/bin/env bash

# Check if we got argument to set up QA deps.
QA_ENV=""
if [ "$1" == "-q" ] || [ "$2" == "-q" ]; then
  QA_ENV="--with qa"
fi

# Check if we got argument to force recreation of venv.
FORCE="false"
if [ "$1" == "-f" ] || [ "$2" == "-f" ]; then
  FORCE="true"
fi

# If venv folder doesn't exist, create it.
if [ ! -d "./.venv" ]; then
  echo "Creating .venv environment"
  python -m venv .venv
else
  # If it exist, only recreate it if FORCE arg is passed.
  if [ "$FORCE" == "true" ]; then
    # Remove folder if we want to force recreating it.
    echo "Removing and re-creating .venv environment"
    rm -rf ./.venv
    python -m venv .venv
  fi
fi

# Setup dependencies as needed.
echo "Installing dependencies".
poetry install $QA_ENV
