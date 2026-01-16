#!/bin/bash

set -e

count=$(python3 tools/warnanalyzer.py analyzer.txt)

echo "{\"color\": \"yellow\", \"status\": \"$count\", \"subject\": \"Warnings\"}" > warning_count.txt

echo "Found $count warnings."
