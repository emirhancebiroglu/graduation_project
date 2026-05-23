#!/bin/bash
set -e
cd /home/emirhan/bitirme/data/raw/ctu13_binetflow
echo "Resuming download..."
curl -L -C - -o CTU-13-Dataset.tar.bz2 "https://datasets.rocketgraph.com/CTU-13/CTU-13-Dataset.tar.bz2"
echo "Download complete, extracting..."
bunzip2 -kf CTU-13-Dataset.tar.bz2
tar -xf CTU-13-Dataset.tar
echo "Extraction complete. Contents:"
ls -la
