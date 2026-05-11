#!/bin/bash
cd /home/emirhan/bitirme/demo-app/api
nohup .venv/bin/python -m uvicorn main:app --port 8000 --host 0.0.0.0 --app-dir /home/emirhan/bitirme/demo-app/api &>/tmp/demo-api.log &
echo "Started PID $!"