#!/bin/bash

set -ex

RUST_LOG=trace cargo run --features console-logger -- /Users/brandon/Desktop/win64-emulator/assets/enigma_test_protected.exe
