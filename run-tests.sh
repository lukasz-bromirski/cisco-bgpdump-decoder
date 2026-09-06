#!/bin/sh
# Run the full test suite. No dependencies beyond the Python stdlib.
set -e
cd "$(dirname "$0")"
PY="${PYTHON:-python3}"
"$PY" -W error::ResourceWarning -m unittest discover -s tests -t . -v
