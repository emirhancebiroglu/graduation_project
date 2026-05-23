#!/usr/bin/env python3
"""
print_cpp_scaler.py -- Print C++ g_scaler block from scaler JSON sidecar

Usage:
  python3 scripts/print_cpp_scaler.py models/portscan_aggregator_model_v2_scaler.json
"""
import json, sys
from pathlib import Path

path = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("models/portscan_aggregator_model_v2_scaler.json")
data = json.loads(path.read_text())
median = data['median']
iqr = data['iqr']

m_str = ', '.join(f'{v:.10f}' for v in median)
q_str = ', '.join(f'{v:.10f}' for v in iqr)

print("// AGG_SCALER_PARAMS_BEGIN")
print("PsiAggScalerParams g_scaler = {")
print(f"    {{ {m_str} }},")
print(f"    {{ {q_str} }}")
print("};")
print("// AGG_SCALER_PARAMS_END")