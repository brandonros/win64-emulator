#!/bin/bash

# Start container system if needed
if ! container list --all >/dev/null 2>&1; then
    echo "Starting container system..."
    container system start
fi

# Check if win64-emulator image exists, build if not found
if ! container images ls | grep -q win64-emulator; then
    container build -t win64-emulator:0.0.1 .
else
    echo "win64-emulator image found"
fi

container run --rm -it --memory 8G -v $(pwd):/mnt win64-emulator
