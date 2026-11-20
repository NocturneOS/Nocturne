#!/bin/bash

set -e

echo '+ Compiling ReleaseOpt'
cmake --build cmake-build-release-opt/ -j$(nproc) -- iso

echo '+ [x64] Compiling ReleaseOpt'
cmake --build cmake-build-release-opt64/ -j$(nproc) -- iso
