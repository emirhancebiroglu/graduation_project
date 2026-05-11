xgb_fp = 7679
comm_fp = 51343
fp_gap = comm_fp - xgb_fp
wrong_hrs = fp_gap * 6.5 / 60
print(f"FP gap: {fp_gap:,}")
print(f"Wrong hours/day (current formula): {wrong_hrs:.1f}")
print(f"")
print(f"The 6.5 min/FP is per FALSE POSITIVE REVIEWED.")
print(f"This is what ONE analyst saves when reviewing FP alerts.")
print(f"")
print(f"Per day = 43,664 * 6.5 / 60 = {fp_gap * 6.5 / 60:.1f} analyst-hours saved")
print(f"Per week (5 days) = {fp_gap * 6.5 / 60 * 5:.1f} analyst-hours")
print(f"Per month (20 days) = {fp_gap * 6.5 / 60 * 20:.1f} analyst-hours")