#!/usr/bin/env python3
"""
prepare_dos_specialist_dataset.py — DoS Hulk + GoldenEye Specialist için
                                    XGBoost eğitim verisi hazırlama.

BİTİRME PROJESİ — DoS Pilot (Phase 1)
=====================================
Hedef: CIC-IDS2017 CSV dosyalarından DoS Hulk + GoldenEye specialist için
       binary classification eğitim verisi hazırlamak.

Çıktı:
  - DoS pos: Hulk + GoldenEye flow'ları (~241K)
  - Non-DoS neg: BENIGN (undersample) + diğer saldırılar (DDoS, PortScan, BF)
  - 17-feature genişletilmiş set (mevcut 11 + 6 DoS-spesifik)
  - max_packets simülasyonu için sınırlandırılmış varyantlar

Kullanım:
  cd ~/bitirme
  python data_prep/prepare_dos_specialist_dataset.py \\
      --csv-dir   data/raw/cicids2017 \\
      --output-dir data/processed/dos_specialist \\
      --max-packets 2 4 8 full \\
      --seed 42

Çıktı yapısı:
  data/processed/dos_specialist/
    ├── full/                       # max_packets=full (orijinal CIC features)
    │   ├── X_train.npy
    │   ├── y_train.npy
    │   ├── X_val.npy
    │   ├── y_val.npy
    │   ├── X_test.npy
    │   ├── y_test.npy
    │   ├── feature_names.json
    │   └── metadata.json
    ├── mp_8/                       # max_packets=8 simülasyonu
    │   └── ... (aynı yapı)
    ├── mp_4/
    ├── mp_2/
    └── README.md
"""

import argparse
import json
import logging
import sys
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split

# ───────────────────────────────────────────────────────────────
# Logging
# ───────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
log = logging.getLogger(__name__)

# ───────────────────────────────────────────────────────────────
# Saldırı sınıflandırması
# ───────────────────────────────────────────────────────────────
DOS_LABELS = {
    "DoS Hulk",
    "DoS GoldenEye",
}

# Negative class: hem BENIGN hem diğer saldırılar
# Specialist "DoS değil" diyebilmeli — diğer saldırı tiplerini de görmeli
OTHER_ATTACK_LABELS = {
    "DDoS",
    "PortScan",
    "FTP-Patator",
    "SSH-Patator",
    "Bot",
    "DoS Slowhttptest",  # NOT: Slow DoS variantları DOS_LABELS'dan ayrı tutuldu
    "DoS slowloris",     # Çünkü farklı detection signature gerekiyor (slow vs flood)
    # Bu seçim önemli: pilot HULK+GoldenEye'a (volumetric HTTP DoS) odaklı
    # Slow DoS variantları sonraki specialist'e bırakılıyor
}

BENIGN_LABEL = "BENIGN"

# ───────────────────────────────────────────────────────────────
# CIC-IDS2017 → Genişletilmiş 17 feature haritalaması
# ───────────────────────────────────────────────────────────────
# CIC-IDS2017 CSV'sinde column adları (whitespace var, normalize edilecek)
# Bu liste DOS_PILOT_RESEARCH.md §1.4'teki 17-feature setiyle birebir uyumlu

# Mevcut 11 feature (UNSW analoğu) — CIC-IDS2017 column adı eşleştirmesi
EXISTING_11_FEATURES = {
    "dur":      "Flow Duration",          # microseconds
    "sbytes":   "Total Length of Fwd Packets",
    "dbytes":   "Total Length of Bwd Packets",
    "spkts":    "Total Fwd Packets",
    "dpkts":    "Total Backward Packets",
    "sload":    "Flow Bytes/s",           # yaklaşık (proxy)
    "dload":    "Flow Packets/s",         # yaklaşık (proxy)
    "sintpkt":  "Fwd IAT Mean",           # microseconds
    "dintpkt":  "Bwd IAT Mean",
    "swin":     "Init_Win_bytes_forward",
    "dwin":     "Init_Win_bytes_backward",
}

# Yeni 6 feature (DoS-spesifik)
NEW_6_FEATURES = {
    "flow_iat_mean":   "Flow IAT Mean",
    "flow_iat_std":    "Flow IAT Std",
    "pkt_len_mean":    "Average Packet Size",      # CIC ekvivalan
    "pkt_len_std":     "Packet Length Std",
    "rst_flag_count":  "RST Flag Count",
    "urg_flag_count":  "URG Flag Count",
}

ALL_17_FEATURES = {**EXISTING_11_FEATURES, **NEW_6_FEATURES}
FEATURE_NAMES = list(ALL_17_FEATURES.keys())

# ───────────────────────────────────────────────────────────────
# Yardımcı fonksiyonlar
# ───────────────────────────────────────────────────────────────
def normalize_columns(df: pd.DataFrame) -> pd.DataFrame:
    """CSV column adlarındaki whitespace'leri temizle."""
    df.columns = df.columns.str.strip()
    return df


def load_cicids2017_csv(csv_path: Path) -> pd.DataFrame | None:
    """Tek CIC-IDS2017 CSV'si yükle. Hatalıysa None döndür."""
    try:
        df = pd.read_csv(
            csv_path,
            low_memory=False,
            on_bad_lines="skip",
            encoding="utf-8",
            encoding_errors="replace",
        )
        df = normalize_columns(df)
        if "Label" not in df.columns:
            log.warning("Label column yok: %s", csv_path.name)
            return None
        return df
    except Exception as e:
        log.warning("Yüklenemedi (%s): %s", csv_path.name, e)
        return None


def extract_features(df: pd.DataFrame, max_packets: int | None = None) -> pd.DataFrame:
    """
    17 feature'ı çıkar.

    [VARSAYIM] CIC-IDS2017 column adları DOS_PILOT_RESEARCH.md'deki gibi
    standart. Eğer farklı isimde varsa burada catch ediliyor.

    max_packets: Eğer None ise tam flow feature'ları kullan.
                 Eğer integer ise, ilk N paket için feature simülasyonu yap.
                 NOT: CSV'lerde paket-by-paket bilgi yok; bu yüzden
                 simülasyon "yaklaşık" oluyor (ratio scaling).
    """
    # Eksik column'ları tespit et
    missing = [
        cic_col for cic_col in ALL_17_FEATURES.values()
        if cic_col not in df.columns
    ]
    if missing:
        log.warning("Eksik column'lar: %s", missing)
        # Eksik column'ları 0 ile doldur (model eğitebilsin)
        for col in missing:
            df[col] = 0.0

    out = pd.DataFrame()
    for our_name, cic_name in ALL_17_FEATURES.items():
        out[our_name] = pd.to_numeric(df[cic_name], errors="coerce").fillna(0.0)

    # ───────── max_packets simülasyonu ─────────
    # CIC-IDS2017 CSV tam-flow feature'ları içeriyor.
    # max_packets=2 simülasyonu için: total_packets > 2 ise feature'ları
    # ilk 2 pakete ölçekle.
    #
    # [VARSAYIM] Bu yaklaşım kabataslak. Gerçek paket-by-paket simülasyon
    # için PCAP'den Snort3 inspector ile feature çıkarmak gerekir.
    # Bu script o ideal değil ama "approximation" sağlıyor.
    #
    # Mantık: spkts+dpkts > max_packets ise:
    #   - dur, sbytes, dbytes oransal kısaltılır
    #   - flow_iat_*, pkt_len_* korunur (per-packet stat'ler değişmez)
    #   - flag_count'lar oransal kısaltılır
    #   - swin, dwin korunur (ilk paket window değeri)
    if max_packets is not None and max_packets > 0:
        total_pkts = (out["spkts"] + out["dpkts"]).clip(lower=1)
        scale = np.minimum(1.0, max_packets / total_pkts)

        # Volume-bazlı feature'lar oranla küçülür
        for col in ["dur", "sbytes", "dbytes", "spkts", "dpkts",
                    "rst_flag_count", "urg_flag_count"]:
            out[col] = (out[col] * scale).astype(np.float64)

        # sload/dload yeniden hesaplanır (rate metrics)
        # Snort'ta zaten dur sıfırsa bu undefined, dikkat
        with np.errstate(divide="ignore", invalid="ignore"):
            new_dur_sec = np.where(out["dur"] > 0, out["dur"] / 1e6, 1e-6)
            out["sload"] = (out["sbytes"] * 8) / new_dur_sec  # bps
            out["dload"] = (out["dbytes"] * 8) / new_dur_sec

        # IAT'lar sample sayısına göre scale edilir
        # Tek paket varsa IAT zaten 0
        # spkts/dpkts artık scale edilmiş halde
        # Per-packet stat'ler korunur (mean/std değişmez varsayımı)

        # Inf/NaN temizliği
        out = out.replace([np.inf, -np.inf], 0.0).fillna(0.0)

    # Genel inf/NaN temizliği
    out = out.replace([np.inf, -np.inf], 0.0).fillna(0.0)
    return out


def label_to_class(label) -> int | None:
    """Label string'i → binary class. Bilinmeyen ise None."""
    if not isinstance(label, str):
        return None
    label = label.strip()
    
    if label in DOS_LABELS:
        return 1  # Positive: DoS Hulk veya GoldenEye
    if label == BENIGN_LABEL or label in OTHER_ATTACK_LABELS:
        return 0  # Negative: BENIGN veya diğer saldırı
    # Slow DoS, Heartbleed, Web Attack, Infiltration → atlanır
    return None


def build_dataset(csv_dir: Path,
                  max_packets: int | None,
                  seed: int = 42) -> tuple[np.ndarray, np.ndarray, dict]:
    """
    Tüm CIC-IDS2017 CSV'lerini tara, DoS specialist için eğitim seti üret.
    """
    log.info("=" * 60)
    log.info("Dataset oluşturuluyor (max_packets=%s)", max_packets)
    log.info("=" * 60)

    pos_features = []
    neg_features_benign = []
    neg_features_other_attack = []

    label_counts: dict[str, int] = {}

    csv_files = sorted(csv_dir.glob("*.csv"))
    if not csv_files:
        log.error("CSV bulunamadı: %s", csv_dir)
        sys.exit(1)

    for csv_file in csv_files:
        log.info("Yükleniyor: %s", csv_file.name)
        df = load_cicids2017_csv(csv_file)
        if df is None:
            continue

        # Label dağılımı
        for label, count in df["Label"].value_counts().items():
            label_counts[label] = label_counts.get(label, 0) + int(count)

        # Feature'ları çıkar (TÜM satırlar için bir kez)
        feats = extract_features(df, max_packets=max_packets)

        # Label'a göre ayır
        for label in df["Label"].unique():
            mask = df["Label"] == label
            sub_feats = feats[mask].values

            cls = label_to_class(label)
            if cls is None:
                continue

            if cls == 1:  # DoS Hulk/GoldenEye
                pos_features.append(sub_feats)
                log.info("  + %s: %d sample (POSITIVE)", label, mask.sum())
            elif label == BENIGN_LABEL:
                neg_features_benign.append(sub_feats)
                log.info("  + BENIGN: %d sample (NEG-benign)", mask.sum())
            else:  # diğer saldırı
                neg_features_other_attack.append(sub_feats)
                log.info("  + %s: %d sample (NEG-other_attack)", label, mask.sum())

    # Birleştir
    if not pos_features:
        log.error("Hiç DoS Hulk/GoldenEye sample bulunamadı!")
        sys.exit(1)

    X_pos = np.vstack(pos_features)
    X_neg_benign = np.vstack(neg_features_benign) if neg_features_benign else np.empty((0, 17))
    X_neg_other = np.vstack(neg_features_other_attack) if neg_features_other_attack else np.empty((0, 17))

    log.info("─" * 60)
    log.info("Toplam DoS pos:           %s", f"{len(X_pos):,}")
    log.info("Toplam BENIGN neg:        %s", f"{len(X_neg_benign):,}")
    log.info("Toplam other-attack neg:  %s", f"{len(X_neg_other):,}")

    # ────────────────────────────────────────────────
    # Negatif sınıf yapılandırması:
    #   - BENIGN'i undersample et (~ pos sayısı kadar)
    #   - other_attack'ları küçük tut (~ %20 of pos)
    # Bu mantık DOS_PILOT_RESEARCH.md §2.4 ile uyumlu
    # ────────────────────────────────────────────────
    rng = np.random.default_rng(seed)

    target_neg_benign_size = len(X_pos)
    target_neg_other_size = max(int(0.2 * len(X_pos)), 50_000)

    if len(X_neg_benign) > target_neg_benign_size:
        idx = rng.choice(len(X_neg_benign), size=target_neg_benign_size, replace=False)
        X_neg_benign = X_neg_benign[idx]

    if len(X_neg_other) > target_neg_other_size:
        idx = rng.choice(len(X_neg_other), size=target_neg_other_size, replace=False)
        X_neg_other = X_neg_other[idx]

    X_neg = np.vstack([X_neg_benign, X_neg_other])

    log.info("Sampling sonrası:")
    log.info("  DoS pos:           %s", f"{len(X_pos):,}")
    log.info("  Non-DoS neg:       %s", f"{len(X_neg):,}")
    log.info("    └─ BENIGN:       %s", f"{len(X_neg_benign):,}")
    log.info("    └─ other_attack: %s", f"{len(X_neg_other):,}")

    # X, y birleştir
    X = np.vstack([X_pos, X_neg]).astype(np.float32)
    y = np.concatenate([
        np.ones(len(X_pos), dtype=np.int8),
        np.zeros(len(X_neg), dtype=np.int8),
    ])

    metadata = {
        "max_packets": max_packets if max_packets else "full",
        "n_samples": int(len(X)),
        "n_pos": int(len(X_pos)),
        "n_neg": int(len(X_neg)),
        "n_neg_benign": int(len(X_neg_benign)),
        "n_neg_other_attack": int(len(X_neg_other)),
        "n_features": int(X.shape[1]),
        "feature_names": FEATURE_NAMES,
        "label_counts_raw": label_counts,
        "pos_labels": sorted(DOS_LABELS),
        "neg_labels_attacks": sorted(OTHER_ATTACK_LABELS),
        "seed": seed,
    }

    return X, y, metadata


def split_and_save(X: np.ndarray,
                   y: np.ndarray,
                   metadata: dict,
                   output_dir: Path,
                   seed: int = 42) -> None:
    """Train/Val/Test 70/15/15 stratified split → kaydet."""
    output_dir.mkdir(parents=True, exist_ok=True)

    # 70/15/15 stratified
    X_temp, X_test, y_temp, y_test = train_test_split(
        X, y, test_size=0.15, stratify=y, random_state=seed,
    )
    X_train, X_val, y_train, y_val = train_test_split(
        X_temp, y_temp, test_size=0.1764, stratify=y_temp, random_state=seed,
        # 0.1764 → kalan setin %17.64'ü = total'ın %15'i
    )

    log.info("Split sonuçları:")
    log.info("  Train: %s (pos=%d, neg=%d)",
             f"{len(X_train):,}", int(y_train.sum()), int((y_train == 0).sum()))
    log.info("  Val:   %s (pos=%d, neg=%d)",
             f"{len(X_val):,}", int(y_val.sum()), int((y_val == 0).sum()))
    log.info("  Test:  %s (pos=%d, neg=%d)",
             f"{len(X_test):,}", int(y_test.sum()), int((y_test == 0).sum()))

    np.save(output_dir / "X_train.npy", X_train)
    np.save(output_dir / "y_train.npy", y_train)
    np.save(output_dir / "X_val.npy",   X_val)
    np.save(output_dir / "y_val.npy",   y_val)
    np.save(output_dir / "X_test.npy",  X_test)
    np.save(output_dir / "y_test.npy",  y_test)

    metadata["split"] = {
        "train": int(len(X_train)),
        "val":   int(len(X_val)),
        "test":  int(len(X_test)),
    }
    with open(output_dir / "metadata.json", "w") as f:
        json.dump(metadata, f, indent=2, default=str)

    with open(output_dir / "feature_names.json", "w") as f:
        json.dump(FEATURE_NAMES, f, indent=2)

    log.info("Kaydedildi: %s", output_dir)


def write_readme(parent_output: Path, max_packets_list: list) -> None:
    """Klasör yapısını açıklayan README üret."""
    readme = parent_output / "README.md"
    with open(readme, "w") as f:
        f.write("# DoS Specialist — Eğitim Seti\n\n")
        f.write("Pilot için CIC-IDS2017'den hazırlanmış DoS Hulk + GoldenEye binary classifier dataseti.\n\n")
        f.write("## Klasör Yapısı\n\n")
        for mp in max_packets_list:
            label = "full" if mp is None else f"mp_{mp}"
            f.write(f"- `{label}/` — max_packets={'tam flow' if mp is None else mp} simülasyonu\n")
        f.write("\n## İçerik\n\n")
        f.write("Her klasörde:\n")
        f.write("- `X_train.npy`, `y_train.npy` — eğitim seti\n")
        f.write("- `X_val.npy`, `y_val.npy` — validation\n")
        f.write("- `X_test.npy`, `y_test.npy` — test\n")
        f.write("- `feature_names.json` — feature isimleri (sıralı)\n")
        f.write("- `metadata.json` — sample sayıları, label dağılımı\n")
        f.write("\n## Sonraki Adım\n\n")
        f.write("```bash\npython train/train_dos_specialist.py --data-dir data/processed/dos_specialist\n```\n")


# ───────────────────────────────────────────────────────────────
# Main
# ───────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description="DoS Specialist (Hulk + GoldenEye) için eğitim verisi hazırla",
    )
    parser.add_argument(
        "--csv-dir",
        type=Path,
        required=True,
        help="CIC-IDS2017 CSV dizini (örn: data/raw/cicids2017)",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        required=True,
        help="Çıktı dizini (örn: data/processed/dos_specialist)",
    )
    parser.add_argument(
        "--max-packets",
        nargs="+",
        default=["2", "4", "8", "full"],
        help="max_packets varyantları (default: 2 4 8 full)",
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=42,
    )
    args = parser.parse_args()

    if not args.csv_dir.exists():
        log.error("CSV dizini yok: %s", args.csv_dir)
        sys.exit(1)

    args.output_dir.mkdir(parents=True, exist_ok=True)

    # Her max_packets varyantı için ayrı set üret
    max_packets_list = []
    for mp in args.max_packets:
        if mp.lower() == "full":
            max_packets_list.append(None)
        else:
            max_packets_list.append(int(mp))

    for mp in max_packets_list:
        label = "full" if mp is None else f"mp_{mp}"
        output_subdir = args.output_dir / label

        log.info("\n" + "=" * 70)
        log.info("VARYANT: %s", label)
        log.info("=" * 70)

        X, y, metadata = build_dataset(args.csv_dir, max_packets=mp, seed=args.seed)
        split_and_save(X, y, metadata, output_subdir, seed=args.seed)

    write_readme(args.output_dir, max_packets_list)
    log.info("\n✅ TAMAMLANDI: %s", args.output_dir)


if __name__ == "__main__":
    main()