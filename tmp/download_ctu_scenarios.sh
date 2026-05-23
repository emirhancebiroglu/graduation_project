#!/bin/bash
set -e
OUTDIR=/home/emirhan/bitirme/data/raw/ctu13_binetflow
mkdir -p "$OUTDIR"
cd "$OUTDIR"

# Try the scenario download pages. They contain detailed-bidirectional-flow-labels/
# Individual scenario pages:
BASE="https://mcfp.felk.cvut.cz/publicDatasets/CTU-Malware-Capture-Botnet"

for i in $(seq 42 54); do
    # Try to get directory listing and find binetflow files
    URL="${BASE}-${i}/detailed-bidirectional-flow-labels/"
    echo "Checking $URL ..."
    LISTING=$(curl -sL "$URL" 2>/dev/null | grep -oP 'href="[^"]+\.binetflow[^"]*"' | head -5)
    if [ -n "$LISTING" ]; then
        echo "  Found binetflow files!"
        for f in $LISTING; do
            fname=$(echo "$f" | sed 's/href="//;s/"//')
            curl -L -o "${i}_${fname}" "${URL}${fname}" &
        done
    else
        echo "  No binetflow files found at this URL"
        # Try alternative URL patterns
        curl -sL "$URL" 2>/dev/null | grep -oP 'href="[^"]+\.(binetflow|csv)"' | head -5
    fi
done

wait
echo "=== Done ==="
ls -lh *.binetflow *.csv 2>/dev/null | head -30
