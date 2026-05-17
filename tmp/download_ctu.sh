#!/bin/bash
set -e
OUTDIR=/home/emirhan/bitirme/data/raw/ctu13_binetflow
mkdir -p "$OUTDIR"

# Try rocketgraph mirror for the big tar
echo "=== Trying rocketgraph mirror ==="
if curl -sI "https://datasets.rocketgraph.com/CTU-13/CTU-13-Dataset.tar.bz2" 2>/dev/null | grep -q "200\|302"; then
    echo "Mirror available! Downloading..."
    cd "$OUTDIR"
    curl -L -o CTU-13-Dataset.tar.bz2 "https://datasets.rocketgraph.com/CTU-13/CTU-13-Dataset.tar.bz2"
    echo "Extracting..."
    tar -xjf CTU-13-Dataset.tar.bz2
    echo "Done"
    exit 0
fi

# Try individual scenarios
echo "=== Trying individual scenarios ==="
BASE="https://mcfp.felk.cvut.cz/publicDatasets/CTU-Malware-Capture-Botnet"
# Each scenario has the biargus/binflow in detailed-bidirectional-flow-labels/
for i in $(seq 42 54); do
    URL="${BASE}-${i}/detailed-bidirectional-flow-labels/"
    echo "Checking scenario ${i}..."
    code=$(curl -sI "${URL}" 2>/dev/null | head -1)
    echo "  ${URL} -> ${code}"
done

echo "=== Trying main directory listing ==="
curl -sL "https://mcfp.felk.cvut.cz/publicDatasets/CTU-13-Dataset/" 2>/dev/null | head -50
