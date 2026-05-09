"""
analyze_max_packets.py — Saldırı Türü Bazında Optimal max_packets Analizi
Bitirme Projesi: IDS Performans Karşılaştırma

ÇALIŞTIRMA:
  cd ~/bitirme
  python3 scripts/analyze_max_packets.py

ÇIKTILAR:
  1. Paket dağılımı: Her saldırı türü için p10/p25/p50/p75/p90 + dominant port
  2. Coverage tablosu: max_pkt=2,4,6,8,10,14,20'de flow coverage oranları
  3. Score simülasyonu: Partial flow feature sim → LSTM model → recall@threshold
  4. Öneri tablosu: port_overrides için önerilen değerler

NOT: Score simülasyonu yaklaşıktır (gerçek Snort3 inference'ından farklı olabilir).
Coverage tablosu deterministiktir ve port_overrides kararı için yeterlidir.
"""

import os, sys, warnings
import pandas as pd
import numpy as np

warnings.filterwarnings('ignore')
os.environ["TF_CPP_MIN_LOG_LEVEL"] = "3"

HOME    = os.path.expanduser('~')
CSV_DIR = os.path.join(HOME, 'bitirme', 'data', 'raw', 'cicids2017')

# ─── Scaler parametreleri (attack_analysis.py'den, v3 model ile aynı) ────────
MEDIAN = np.array([0.0157434195, 2.5649493575, 2.5649493575, 7.2936977206,
                   7.5071410797, 73.0,         89.0,         255.0,
                   255.0,        0.3841277437, 0.3471507323])
IQR    = np.array([0.1934837207, 2.7080502011, 2.6625878270, 2.7622745192,
                   4.4213950593, 72.0,         496.0,        255.0,
                   255.0,        2.1157851784, 1.9696133626])

FEATURE_ORDER = ['dur','spkts','dpkts','sbytes','dbytes',
                 'smeansz','dmeansz','swin','dwin','sintpkt','dintpkt']
LOG_COLS      = ['dur','spkts','dpkts','sbytes','dbytes','sintpkt','dintpkt']

MAX_PKT_SWEEP = [2, 4, 6, 8, 10, 14, 20]
THRESHOLD     = 0.55    # v2/v3/v5 default threshold

# CIC-IDS2017 → gerçek portlar (bilinen saldırı-port eşlemeleri)
KNOWN_PORTS = {
    'FTP-Patator':   [21],
    'SSH-Patator':   [22],
    'DoS Hulk':      [80],
    'DoS slowloris': [80],
    'DoS GoldenEye': [80],
    'DoS Slowhttptest': [80],
    'DDoS':          [80],
    'PortScan':      [],          # port sweep — çok çeşitli
    'Bot':           [],          # C2 → rastgele
    'Web Attack – Brute Force':  [80, 443],
    'Web Attack – XSS':          [80, 443],
    'Web Attack – Sql Injection':[80, 443],
    'Infiltration':  [],
    'Heartbleed':    [443],
}


# ─── Yardımcı: sütun adı esnek okuma ─────────────────────────────────────────
def gc(df, names, default=0.0):
    for n in names:
        if n in df.columns:
            return pd.to_numeric(df[n], errors='coerce').fillna(default)
    return pd.Series(default, index=df.index, dtype=float)


# ─── Tüm CSV'leri oku, saldırı bazında topla ──────────────────────────────────
def load_all():
    """CIC-IDS2017 CSV'lerini oku, attack label → DataFrame sözlüğü döndür."""
    if not os.path.isdir(CSV_DIR):
        print(f"HATA: CSV dizini bulunamadı: {CSV_DIR}")
        sys.exit(1)

    attack_data = {}    # label → list of DataFrames
    dest_port_data = {} # label → list of dest port Series

    csv_files = sorted(f for f in os.listdir(CSV_DIR) if f.endswith('.csv'))
    if not csv_files:
        print(f"HATA: {CSV_DIR} içinde CSV bulunamadı.")
        sys.exit(1)

    print(f"CSV dizini: {CSV_DIR}")
    print(f"{len(csv_files)} dosya bulundu. Okunuyor...\n")

    for fname in csv_files:
        path = os.path.join(CSV_DIR, fname)
        try:
            df = pd.read_csv(path, low_memory=False,
                             on_bad_lines='skip', encoding_errors='replace')
            df.columns = df.columns.str.strip()
            if 'Label' not in df.columns:
                continue
            df['Label'] = df['Label'].astype(str).str.strip()
            df = df[df['Label'].str.len() > 0]
        except Exception as e:
            print(f"  [ATLA] {fname}: {e}")
            continue

        # Paket sayısı sütunları
        spkts = gc(df, ['Total Fwd Packets', ' Total Fwd Packets'])
        dpkts = gc(df, ['Total Backward Packets', ' Total Backward Packets'])
        total = (spkts + dpkts).clip(lower=1)

        # Hedef port (varsa)
        dport = gc(df, ['Destination Port', ' Destination Port',
                        'Dst Port', 'dst_port'], default=-1)

        # Diğer feature'lar
        dur     = gc(df, ['Flow Duration', ' Flow Duration']) / 1e6
        sbytes  = gc(df, ['Total Length of Fwd Packets', ' Total Length of Fwd Packets'])
        dbytes  = gc(df, ['Total Length of Bwd Packets', ' Total Length of Bwd Packets'])
        smeansz = gc(df, ['Fwd Packet Length Mean', ' Fwd Packet Length Mean'])
        dmeansz = gc(df, ['Bwd Packet Length Mean', ' Bwd Packet Length Mean'])
        swin    = gc(df, ['Init_Win_bytes_forward', ' Init_Win_bytes_forward']).clip(upper=1020)
        dwin    = gc(df, ['Init_Win_bytes_backward', ' Init_Win_bytes_backward']).clip(upper=1020)
        sintpkt = gc(df, ['Fwd IAT Mean', ' Fwd IAT Mean']) / 1000.0
        dintpkt = gc(df, ['Bwd IAT Mean', ' Bwd IAT Mean']) / 1000.0

        feat_df = pd.DataFrame({
            'total_pkts': total.values,
            'spkts':      spkts.values,
            'dpkts':      dpkts.values,
            'dur':        dur.values,
            'sbytes':     sbytes.values,
            'dbytes':     dbytes.values,
            'smeansz':    smeansz.values,
            'dmeansz':    dmeansz.values,
            'swin':       swin.values,
            'dwin':       dwin.values,
            'sintpkt':    sintpkt.values,
            'dintpkt':    dintpkt.values,
            'dport':      dport.values,
        })

        print(f"  {fname}: {len(df):,} satır")

        for label in df['Label'].unique():
            mask = (df['Label'] == label).values
            subset = feat_df[mask].copy()
            if label not in attack_data:
                attack_data[label] = []
            attack_data[label].append(subset)

    print()

    # Birleştir
    combined = {}
    for label, dfs in attack_data.items():
        combined[label] = pd.concat(dfs, ignore_index=True)

    return combined


# ─── Partial flow feature simülasyonu ────────────────────────────────────────
def simulate_partial(row, max_pkt):
    """
    Tam flow'dan partial (ilk max_pkt paket) feature vektörü üret.

    Fiziksel anlamı: Snort3 inspector max_pkt paketi gördükten sonra
    inference trigger eder. Bu noktada sadece kısmi bilgi var.

    Varsayımlar:
    - spkts / dpkts: toplam paketin oranı korunarak kırpılır
    - sbytes / dbytes: paket sayısına orantılı kırpılır
    - smeansz / dmeansz: sabit (paket başına ortalama boyut değişmez)
    - swin / dwin: sabit (TCP handshake'ten, ilk pakette belirlenir)
    - sintpkt / dintpkt: max_pkt >= 3 ise orijinal değer;
                         max_pkt == 2 ise 0 (1 interval, neredeyse anlık);
                         max_pkt == 1 ise 0
    - dur: oranla kırpılır; max_pkt <= 2 ise 0 kabul edilir
    """
    total  = max(float(row['total_pkts']), 1.0)
    ratio  = min(1.0, max_pkt / total)

    spkts_f = max(1.0, round(float(row['spkts']) * ratio))
    dpkts_f = max(0.0, float(max_pkt) - spkts_f)

    sbytes_f = float(row['sbytes']) * (spkts_f / max(float(row['spkts']), 1.0))
    dbytes_f = float(row['dbytes']) * (dpkts_f / max(float(row['dpkts']), 1.0)) \
               if float(row['dpkts']) > 0 else 0.0

    # Zaman tabanlı özellikler
    if max_pkt <= 2:
        dur_f     = 0.0
        sintpkt_f = 0.0
        dintpkt_f = 0.0
    else:
        dur_f     = float(row['dur']) * ratio
        sintpkt_f = float(row['sintpkt'])  # IAT mean sabit varsayım
        dintpkt_f = float(row['dintpkt']) if dpkts_f >= 2 else 0.0

    return np.array([
        dur_f, spkts_f, dpkts_f, sbytes_f, dbytes_f,
        float(row['smeansz']), float(row['dmeansz']),
        float(row['swin']), float(row['dwin']),
        sintpkt_f, dintpkt_f
    ], dtype=np.float64)


def preprocess_features(X_raw: np.ndarray) -> np.ndarray:
    """log1p + RobustScaler — attack_analysis.py ile aynı."""
    X = X_raw.copy()
    log_idx = [FEATURE_ORDER.index(c) for c in LOG_COLS]
    X[:, log_idx] = np.log1p(np.clip(X[:, log_idx], 0, None))
    X = (X - MEDIAN) / IQR
    return np.nan_to_num(X, nan=0.0, posinf=0.0, neginf=0.0).astype(np.float32)


def load_tflite_model():
    """Kullanılabilir TFLite modelini yükle. Yoksa None döndür."""
    candidates = [
        os.path.join(HOME, 'bitirme', 'models', 'fine_tuned_lstm_model_v5.tflite'),
    ]
    try:
        import tensorflow as tf
        for path in candidates:
            if os.path.exists(path):
                interp = tf.lite.Interpreter(model_path=path)
                interp.allocate_tensors()
                print(f"  TFLite model yüklendi: {os.path.basename(path)}")
                return interp, path
        print("  [UYARI] TFLite model bulunamadı — score simülasyonu atlanacak.")
        return None, None
    except ImportError:
        print("  [UYARI] TensorFlow bulunamadı — score simülasyonu atlanacak.")
        return None, None


def predict_scores(interp, X: np.ndarray) -> np.ndarray:
    """Batch inference — yavaş ama kesin."""
    inp_det = interp.get_input_details()[0]
    out_det = interp.get_output_details()[0]
    scores = np.zeros(len(X), dtype=np.float32)
    Xr = X.reshape(-1, 1, 11)
    for i in range(len(Xr)):
        interp.set_tensor(inp_det['index'], Xr[i:i+1])
        interp.invoke()
        scores[i] = interp.get_tensor(out_det['index'])[0][0]
    return scores


# ─── Dominant port hesaplama ──────────────────────────────────────────────────
def top_ports(series, top_n=3):
    """Bir saldırı türü için en sık görülen destination portları."""
    valid = series[(series > 0) & (series < 65536)]
    if len(valid) == 0:
        return "?"
    vc = valid.value_counts().head(top_n)
    parts = [f"{int(p)}({100*c/len(valid):.0f}%)" for p, c in vc.items()]
    return ", ".join(parts)


# ─── Ana analiz ───────────────────────────────────────────────────────────────
def main():
    sep = "=" * 90

    print(sep)
    print("  analyze_max_packets.py — Saldırı Türü Bazında Optimal max_packets Analizi")
    print(sep)
    print()

    combined = load_all()
    benign   = combined.get('BENIGN', pd.DataFrame())
    attacks  = {k: v for k, v in combined.items() if k != 'BENIGN'}

    # Model yükle (opsiyonel)
    interp, model_name = load_tflite_model()
    has_model = interp is not None

    # Saldırı listesi — N'e göre azalan sıra
    attack_list = sorted(attacks.items(), key=lambda x: len(x[1]), reverse=True)

    # ── BÖLÜM 1: Paket Dağılımı ──────────────────────────────────────────────
    print()
    print(sep)
    print("  BÖLÜM 1: PAKET SAYISI DAĞILIMI (total_pkts = spkts + dpkts)")
    print(sep)
    hdr = f"{'Saldırı Türü':<35} {'N':>7}  {'p10':>5} {'p25':>5} {'p50':>5} {'p75':>5} {'p90':>5} {'p95':>5}  Dominant Port(s)"
    print(hdr)
    print("-" * 90)

    for label, df in attack_list:
        pkts = df['total_pkts'].values
        p = np.percentile(pkts, [10, 25, 50, 75, 90, 95])
        port_str = top_ports(df['dport'])
        print(f"{label:<35} {len(df):>7}  "
              f"{p[0]:>5.0f} {p[1]:>5.0f} {p[2]:>5.0f} "
              f"{p[3]:>5.0f} {p[4]:>5.0f} {p[5]:>5.0f}  {port_str}")

    # BENIGN
    if not benign.empty:
        pkts = benign['total_pkts'].values
        p = np.percentile(pkts, [10, 25, 50, 75, 90, 95])
        port_str = top_ports(benign['dport'])
        print("-" * 90)
        print(f"{'BENIGN':<35} {len(benign):>7}  "
              f"{p[0]:>5.0f} {p[1]:>5.0f} {p[2]:>5.0f} "
              f"{p[3]:>5.0f} {p[4]:>5.0f} {p[5]:>5.0f}  {port_str}")

    # ── BÖLÜM 2: Coverage Tablosu ────────────────────────────────────────────
    print()
    print(sep)
    print("  BÖLÜM 2: FLOW COVERAGE ORANI (% flow'ların kaçında total_pkts <= max_pkt)")
    print("  Yorum: cov@N = max_pkt=N ile flow'un TAMAMI görülür (partial değil)")
    print(sep)

    col_w = 7
    header_parts = ["Saldırı Türü".ljust(35), f"{'N':>7}"]
    for mp in MAX_PKT_SWEEP:
        header_parts.append(f"{'@'+str(mp):>{col_w}}")
    print("  " + "  ".join(header_parts))
    print("  " + "-" * 85)

    coverage_results = {}  # label → {max_pkt: coverage}
    for label, df in attack_list:
        pkts = df['total_pkts'].values
        row_parts = [label.ljust(35), f"{len(df):>7}"]
        cov_dict = {}
        for mp in MAX_PKT_SWEEP:
            cov = (pkts <= mp).mean()
            cov_dict[mp] = cov
            row_parts.append(f"{cov*100:>{col_w}.1f}%")
        coverage_results[label] = cov_dict
        print("  " + "  ".join(row_parts))

    # ── BÖLÜM 3: Score Simülasyonu ───────────────────────────────────────────
    if has_model:
        print()
        print(sep)
        print(f"  BÖLÜM 3: SIMÜLE EDİLMİŞ RECALL (model: {os.path.basename(model_name)})")
        print(f"  threshold = {THRESHOLD}")
        print("  NOT: Partial flow simülasyonu yaklaşıktır. Gerçek Snort3 değerlerinden farklı olabilir.")
        print(sep)

        # BENIGN FP taban (max_pkt=2 için)
        benign_fp_base = {}
        if not benign.empty:
            print("  BENIGN FPR hesaplanıyor (oran örneği, 50K)...")
            ben_sample = benign.sample(min(50000, len(benign)), random_state=42)
            for mp in MAX_PKT_SWEEP:
                X_raw = np.array([simulate_partial(row, mp)
                                  for _, row in ben_sample.iterrows()])
                X_sc  = preprocess_features(X_raw)
                sc    = predict_scores(interp, X_sc)
                benign_fp_base[mp] = (sc > THRESHOLD).mean()

            print(f"  BENIGN FPR @ max_pkt: " +
                  "  ".join(f"@{mp}={benign_fp_base[mp]:.4f}" for mp in MAX_PKT_SWEEP))
            print()

        header_parts = ["Saldırı Türü".ljust(35), f"{'N':>7}"]
        for mp in MAX_PKT_SWEEP:
            header_parts.append(f"{'@'+str(mp):>{col_w}}")
        print("  " + "  ".join(header_parts))
        print("  " + "-" * 85)

        score_results = {}
        for label, df in attack_list:
            # Büyük sınıflar için örnekle
            sample_n = min(5000, len(df))
            sample   = df.sample(sample_n, random_state=42)

            row_parts = [label.ljust(35), f"{len(df):>7}"]
            rec_dict  = {}
            print(f"  {label} simüle ediliyor ({sample_n} flow)...", flush=True)
            for mp in MAX_PKT_SWEEP:
                X_raw = np.array([simulate_partial(row, mp)
                                  for _, row in sample.iterrows()])
                X_sc  = preprocess_features(X_raw)
                sc    = predict_scores(interp, X_sc)
                recall = (sc > THRESHOLD).mean()
                rec_dict[mp] = recall
                row_parts.append(f"{recall:>{col_w}.3f}")
            score_results[label] = rec_dict
            print("  " + "  ".join(row_parts))
    else:
        score_results = {}

    # ── BÖLÜM 4: Öneri Tablosu ───────────────────────────────────────────────
    print()
    print(sep)
    print("  BÖLÜM 4: port_overrides ÖNERİSİ")
    print("  Kriter: recall >= 0.40 VEYA coverage >= 0.60 sağlayan en küçük max_pkt")
    print(sep)
    print(f"  {'Saldırı Türü':<35} {'Dominant Port':>15}  {'Önerilen max_pkt':>18}  Gerekçe")
    print("  " + "-" * 85)

    for label, df in attack_list:
        pkts = df['total_pkts'].values
        port_str = top_ports(df['dport'], top_n=1).split("(")[0].strip()

        # Coverage-tabanlı seçim
        cov_rec = coverage_results.get(label, {})
        cov_based = None
        for mp in MAX_PKT_SWEEP:
            if cov_rec.get(mp, 0) >= 0.60:
                cov_based = mp
                break

        # Score-tabanlı seçim (varsa)
        score_rec = score_results.get(label, {})
        score_based = None
        for mp in MAX_PKT_SWEEP:
            if score_rec.get(mp, 0) >= 0.40:
                score_based = mp
                break

        # Karar: score var ise score_based, yoksa cov_based
        if score_based is not None:
            chosen = score_based
            reason = f"recall≥0.40 @ {score_based} pkt"
        elif cov_based is not None:
            chosen = cov_based
            reason = f"coverage≥60% @ {cov_based} pkt"
        else:
            best_cov_mp = max(MAX_PKT_SWEEP,
                              key=lambda mp: cov_rec.get(mp, 0))
            best_cov    = cov_rec.get(best_cov_mp, 0)
            chosen      = 2  # fallback: default
            reason      = f"coverage={best_cov*100:.0f}% @ {best_cov_mp} (yetersiz → default=2 kullan)"

        # Port bilgisi
        known_p = KNOWN_PORTS.get(label, [])
        if known_p:
            port_display = str(known_p[0])
        elif port_str and port_str != "?":
            port_display = port_str
        else:
            port_display = "çeşitli (override yok)"

        if port_str in ["-1", "?", ""]:
            port_display = "bilinmiyor"

        print(f"  {label:<35} {port_display:>15}  {chosen:>18}  {reason}")

    print()
    print("  ─── ÖZET: snort_combined.lua için port_overrides string'i ───")
    print()

    # Sadece default'tan farklı olan ve spesifik port'u olan saldırılar
    override_parts = []
    for label, df in attack_list:
        cov_rec   = coverage_results.get(label, {})
        score_rec = score_results.get(label, {})
        known_p   = KNOWN_PORTS.get(label, [])
        if not known_p:
            continue

        score_based = next((mp for mp in MAX_PKT_SWEEP
                            if score_rec.get(mp, 0) >= 0.40), None)
        cov_based   = next((mp for mp in MAX_PKT_SWEEP
                            if cov_rec.get(mp, 0) >= 0.60), None)
        chosen = score_based or cov_based

        if chosen and chosen != 2:  # sadece default'tan farklıysa ekle
            override_parts.append(f"{known_p[0]}:{chosen}")

    if override_parts:
        print(f'  port_overrides = "{",".join(override_parts)}"')
    else:
        print("  (Tüm saldırılar için max_pkt=2 yeterli görünüyor)")

    print()
    print(sep)
    print("  Analiz tamamlandı.")
    print(sep)


if __name__ == '__main__':
    main()