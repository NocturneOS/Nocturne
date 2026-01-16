#!/bin/bash

set -e

cd rust;

for i in noct-*; do
	echo "==> Testing $i"
	cargo test -p $i;
done
