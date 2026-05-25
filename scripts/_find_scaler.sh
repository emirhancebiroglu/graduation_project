#!/bin/bash
find /home/emirhan/bitirme/plugins/bot_client_inspector -name "*.h" -o -name "*.cc" | while read f; do
    grep -l "log1p\|scaler" "$f" 2>/dev/null && echo "  $f"
done
echo "---"
grep -rn "log1p\|scaler_apply\|apply.*scaler" /home/emirhan/bitirme/plugins/bot_client_inspector/ 2>/dev/null | grep -v ".so" | grep -v Build | head -20
