"""Quick test: DoS model on synthetic C2 traffic features vs actual DoS traffic features."""
import json
import numpy as np
import xgboost as xgb

dos_model = xgb.Booster()
dos_model.load_model('/home/emirhan/bitirme/models/dos_model.json')

# Read scaler from the C++ code (hardcoded in dos_inspector.cc)
# The scaler params are embedded in the code, not in a file
# Let me check dos_inspector.cc for the scaler values
print("DoS model loaded:", dos_model.num_features(), "features expected")
print()

# Check scaler
import subprocess
result = subprocess.run(['grep', '-A5', 'DosScalerParams', 
    '/home/emirhan/bitirme/plugins/dos_inspector/src/dos_inspector.cc'],
    capture_output=True, text=True)
print("Hardcoded scaler in C++:")
print(result.stdout[:500])
