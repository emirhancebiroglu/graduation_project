"""Quick test for shap_explain_alert — run standalone."""
from shap_explain_alert import explain, shap_to_narrative

# Realistic DoS features (v3b schema):
# dur, spkts, dpkts, sbytes, dbytes, smeansz, dmeansz, sintpkt, dintpkt,
# fwd_pkt_mean, bwd_pkt_mean, fin_cnt, ack_cnt, syn_cnt, bwd_iat
dos_features = [0.003, 847.0, 0.0, 42350.0, 0.0, 50.0, 0.0, 0.001, 0.0, 50.0, 0.0, 0.0, 0.0, 1.0, 0.0]

contribs = explain(dos_features)
narrative = shap_to_narrative(contribs)

print("CONTRIBUTIONS:")
for c in contribs:
    print(f"  {c['feature']}: shap={c['shap_value']:.4f} raw={c['raw_value']:.3g} dir={c['direction']}")

print()
print("NARRATIVE:", narrative)
