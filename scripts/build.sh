#!/bin/bash

#container system start
#container build -f scripts/Dockerfile -t rust-windows-build
container run --rm -t --memory 8G -v $(pwd):/mnt rust-windows-build bash -c "
    cd /mnt && 
    cargo build -p advapi32 --target x86_64-pc-windows-gnu &&
    cargo build -p comctl32 --target x86_64-pc-windows-gnu &&
    cargo build -p gdi32 --target x86_64-pc-windows-gnu &&
    cargo build -p kernel32 --target x86_64-pc-windows-gnu &&
    cargo build -p ntdll --target x86_64-pc-windows-gnu &&
    cargo build -p ole32 --target x86_64-pc-windows-gnu &&
    cargo build -p oleaut32 --target x86_64-pc-windows-gnu &&
    cargo build -p shell32 --target x86_64-pc-windows-gnu &&
    cargo build -p user32 --target x86_64-pc-windows-gnu &&
    cargo build -p uxtheme --target x86_64-pc-windows-gnu &&
    cargo build -p version --target x86_64-pc-windows-gnu
"
