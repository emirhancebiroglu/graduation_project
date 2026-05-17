#!/bin/bash
echo "=== portscan ==="
grep -n 'model_path\|"mp"\|std::string mp' /home/emirhan/bitirme/plugins/portscan_inspector/src/portscan_inspector.cc
echo "=== dos_agg ==="
grep -n 'model_path\|"mp"\|std::string mp' /home/emirhan/bitirme/plugins/dos_aggregator/src/dos_inspector.cc
echo "=== ddos_agg ==="
grep -n 'model_path\|"mp"\|std::string mp' /home/emirhan/bitirme/plugins/ddos_aggregator/src/ddos_inspector.cc
echo "=== botnet_c2 ==="
grep -n 'model_path\|"mp"\|std::string mp' /home/emirhan/bitirme/plugins/botnet_c2_inspector/src/botnet_c2_inspector.cc
echo "=== bot_client (reference) ==="
grep -n 'model_path\|"mp"\|std::string mp' /home/emirhan/bitirme/plugins/bot_client_inspector/src/bot_client_inspector.cc
