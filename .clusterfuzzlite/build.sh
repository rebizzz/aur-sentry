#!/bin/bash -eu
cargo fuzz build -O
cp fuzz/target/x86_64-unknown-linux-gnu/release/parse_pkgbuild $OUT/
