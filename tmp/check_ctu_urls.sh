#!/bin/bash
urls=(
  "https://mcfp.felk.cvut.cz/publicDatasets/CTU-13-Dataset/capture20110810.binetflow"
  "https://mcfp.felk.cvut.cz/publicDatasets/CTU-13-Dataset/capture20110810/capture20110810.binetflow"
  "https://mcfp.felk.cvut.cz/publicDatasets/CTU-13-Dataset/1-Neris-20110810/capture20110810.binetflow"
  "https://mcfp.felk.cvut.cz/publicDatasets/CTU-13-Dataset/capture20110810-raw.zip"
)
for url in "${urls[@]}"; do
  code=$(curl -sI "$url" 2>/dev/null | head -1)
  echo "$url -> $code"
done
