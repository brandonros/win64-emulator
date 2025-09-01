# Use official Rust image as base
FROM docker.io/library/rust:1.89

# Install cross-compilation dependencies
RUN apt-get update && apt-get install -y \
    gcc-mingw-w64-x86-64 \
    mingw-w64 \
    && rm -rf /var/lib/apt/lists/*

# Add Windows target for Rust
RUN rustup target add x86_64-pc-windows-gnu

# Set up cross-compilation environment
ENV CC_x86_64_pc_windows_gnu=x86_64-w64-mingw32-gcc
ENV CXX_x86_64_pc_windows_gnu=x86_64-w64-mingw32-g++
ENV AR_x86_64_pc_windows_gnu=x86_64-w64-mingw32-ar
ENV CARGO_TARGET_X86_64_PC_WINDOWS_GNU_LINKER=x86_64-w64-mingw32-gcc
