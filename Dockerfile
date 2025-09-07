# syntax=docker/dockerfile:1
# Use cargo-chef to cache dependencies
FROM lukemathwalker/cargo-chef:0.1.72-rust-1.89-trixie AS chef
WORKDIR /app

# Install dependencies
RUN apt-get update && apt-get install -y cmake
RUN cargo install cargo-tarpaulin

# Plan stage - analyze the project and create recipe.json
FROM chef AS planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

# Builder stage - build dependencies first (cached layer), then the application
FROM chef AS builder
COPY --from=planner /app/recipe.json recipe.json
# Build dependencies - this is the caching Docker layer!
# This will be cached as long as your Cargo.toml and Cargo.lock don't change
RUN cargo chef cook --release --recipe-path recipe.json

# Now copy all the source code and build the application
COPY . .

# Build the actual application
RUN cargo build --release --bin win64-emulator

