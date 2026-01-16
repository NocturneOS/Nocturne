#!/bin/bash

rustup toolchain install nightly-2025-09-01
rustup component add rust-src --toolchain nightly-2025-09-01-x86_64-unknown-linux-gnu
