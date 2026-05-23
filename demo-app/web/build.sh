#!/bin/bash
cd /home/emirhan/bitirme/demo-app/web
source ~/.nvm/nvm.sh
node node_modules/next/dist/bin/next build 2>&1 | tail -40