#!/bin/bash

set -e

TESTDIR=$(dirname $0)

PYTHONPATH=$TESTDIR/../

python -m unittest discover -v -s $TESTDIR

