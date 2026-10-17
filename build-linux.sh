#!/bin/bash
# Native Linux build (needs gcc). Output: release/linux/kaevex
set -e
cd "$(dirname "$0")"
mkdir -p release/linux
gcc -O2 -pthread -Wall -Wno-unused -Wno-format-truncation -Wno-misleading-indentation -Wno-stringop-truncation -o release/linux/kaevex src/linux/kaevex-linux.c
echo "built release/linux/kaevex"
