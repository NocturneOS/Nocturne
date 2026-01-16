#!/bin/bash

set -e
set -o pipefail

bash tools/build/compile_builds.sh 2>&1 | tee analyzer.txt
