#!/bin/bash
set -e
OUTDIR=/home/emirhan/bitirme/data/raw/ctu13_binetflow
mkdir -p "$OUTDIR"
cd "$OUTDIR"

if [ -f "CTU-13-Dataset.tar" ]; then
    echo "Tar already exists, extracting..."
else
    if [ -f "CTU-13-Dataset.tar.bz2" ]; then
        echo "bz2 exists, extracting..."
        bunzip2 -kf CTU-13-Dataset.tar.bz2
    else
        echo "Downloading CTU-13 from rocketgraph mirror..."
        curl -L -o CTU-13-Dataset.tar.bz2 "https://datasets.rocketgraph.com/CTU-13/CTU-13-Dataset.tar.bz2"
        echo "Download complete, extracting..."
        bunzip2 -kf CTU-13-Dataset.tar.bz2
    fi
fi
echo "Extracting tar..."
tar -xf CTU-13-Dataset.tar

# Find all binetflow files
echo "=== Binetflow files found ==="
find . -name "*.binetflow" -o -name "*.csv" | head -30

echo ""
echo "=== Contents ==="
ls -la
