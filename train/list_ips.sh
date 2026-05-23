#!/bin/bash
awk '{print $NF}' /tmp/botcl_train_data.txt | sort -u | head -20
