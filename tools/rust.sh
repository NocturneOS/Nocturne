#!/bin/bash

TOOLCHAIN=nightly-2026-01-01

rustup toolchain install ${TOOLCHAIN}
rustup component add rust-src --toolchain ${TOOLCHAIN}-x86_64-unknown-linux-gnu
