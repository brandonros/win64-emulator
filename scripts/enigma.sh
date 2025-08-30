#!/bin/bash

set -ex

RUST_LOG=trace cargo run --release --features file-logger --features log-instruction -- /Users/brandon/Desktop/9.04/aa8e16e3d9b5e0bb43581d3ed1a1776ab32eacd22594a9a691615dfd270bbbf1.dll