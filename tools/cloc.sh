#!/bin/sh

cloc --by-file . --exclude-dir="target,ramdisk" --not-match-d="(cmake-*)" --not-match-f=".*?\.(css|yaml|toml|md|xml)"

