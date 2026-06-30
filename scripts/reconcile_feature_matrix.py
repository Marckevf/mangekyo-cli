"""
reconcile_feature_matrix.py
===========================
Project Mangekyo — one-time feature-matrix reconciliation (pre-v1 freeze).

Rebuilds final_feature_matrix.csv so it carries the explicit `filename` +
`is_synthetic` columns and the synthetic/real split is never inferred again.

Why a union (not a plain re-run of 2_prepare):
  * XML-backed rows (xml_logs/*, incl. all 1,000 synthetic) HAVE XML on disk →
    regenerated deterministically via 2_prepare, fully keyed & correctly labeled.
  * Internet-collected rows (internetdb/, diversity/) were scored LIVE from the
    Shodan InternetDB API at collection time; there is no XML and no cached raw
    JSON, so they CANNOT be regenerated. They are taken as-is from the existing
    matrix (every one preserved) and tagged is_synthetic=0.

Alignment safety (verified before this script runs):
  * The existing matrix is a 100% exact-value, strictly-monotonic subsequence of
    training_data_v2.csv on risk_score + 7 intel columns.
  * The monotonic alignment exhausts the xml_logs block at the head/tail cut, so
    the internet tail contains no synthetic-derived row, and no kept row carries
    a synthetic-exclusive fingerprint.

Output: final_feature_matrix.csv (written only after every assertion passes).
"""

from __future__ import annotations

from pathlib import Path

import numpy as np
import pandas as pd

from mangekyo import feature_extractor as prep

PROJ        = Path(__file__).parent
TRAIN_CSV   = PROJ / "training_data_v2.csv"
FEATURE_CSV = PROJ / "final_feature_matrix.csv"
OUT_TMP     = PROJ / "final_feature_matrix.tmp.csv"

SHARED = ["risk_score", "max_epss_score", "has_high_epss", "has_kev_cve",
          "kev_port_count", "max_nvd_score", "mean_nvd_score", "nvd_zero_count"]


def _keys(df: pd.DataFrame) -> list[tuple]:
    d = df[SHARED].copy()
    for c in SHARED:
        if np.issubdtype(d[c].dtype, np.floating):
            d[c] = d[c].round(6)
    return list(map(tuple, d.values))


def main() -> None:
    td = pd.read_csv(TRAIN_CSV)
    fm = pd.read_csv(FEATURE_CSV)
    print(f"[+] training_data_v2.csv : {len(td):,} rows")
    print(f"[+] final_feature_matrix : {len(fm):,} rows (pre-reconcile)")

    tpref = td["filename"].str.split(r"[\\/]").str[0].values
    xml_end = int((tpref == "xml_logs").sum())

    # ── 1. Re-verify the alignment gate (abort on any failure) ──────────────
    tk, fk = _keys(td), _keys(fm)
    mapping, j = [], 0
    for k in fk:
        jj, found = j, -1
        while jj < len(tk):
            if tk[jj] == k:
                found = jj; break
            jj += 1
        mapping.append(found)
        j = found + 1 if found >= 0 else j

    assert all(m >= 0 for m in mapping), "ABORT: unmatched feature rows"
    matched = [m for m in mapping]
    assert all(matched[i] < matched[i + 1] for i in range(len(matched) - 1)), \
        "ABORT: alignment not strictly monotonic"

    cls = ["xml" if m < xml_end else "net" for m in mapping]
    first_net = cls.index("net")
    last_xml = max(i for i, c in enumerate(cls) if c == "xml")
    assert last_xml < first_net, "ABORT: xml_logs/internet rows interleave"

    synth_keys = {k for k, s in zip(tk, td["is_synthetic"].astype(int)) if s == 1}
    net_keys = {k for k, p in zip(tk, tpref) if p in ("internetdb", "diversity")}
    tail_idx = [i for i, c in enumerate(cls) if c == "net"]
    leak = sum(1 for i in tail_idx if fk[i] in synth_keys and fk[i] not in net_keys)
    assert leak == 0, f"ABORT: {leak} kept rows carry a synthetic-exclusive key"
    print(f"[+] alignment gate PASS — head(xml)={first_net:,}  tail(internet)={len(tail_idx):,}")

    # ── 2. Regenerate the XML-backed rows from disk via feature_extractor ───
    xml_labels = td.iloc[:xml_end].copy()
    tmp_labels = PROJ / "_xml_labels.tmp.csv"
    xml_labels.to_csv(tmp_labels, index=False)
    tmp_xml_out = PROJ / "_xml_features.tmp.csv"
    print("\n[+] Regenerating XML-backed rows from disk ...")
    prep.build_feature_matrix(str(tmp_labels), str(tmp_xml_out))
    fm_xml = pd.read_csv(tmp_xml_out)
    tmp_labels.unlink(); tmp_xml_out.unlink()
    n_syn_xml = int((fm_xml["is_synthetic"] == 1).sum())
    print(f"    XML-backed rows regenerated : {len(fm_xml):,} "
          f"(synthetic={n_syn_xml:,}, real={len(fm_xml) - n_syn_xml:,})")
    assert n_syn_xml == 1000, f"ABORT: expected 1000 synthetic, got {n_syn_xml}"

    # ── 3. Take internet rows as-is, attach filename + is_synthetic=0 ───────
    fm_net = fm.iloc[tail_idx].copy().reset_index(drop=True)
    fm_net["filename"] = [td["filename"].iloc[mapping[i]] for i in tail_idx]
    fm_net["is_synthetic"] = 0
    # schema must match exactly (same feature set, same order)
    assert set(fm_xml.columns) == set(fm_net.columns), (
        "ABORT: column mismatch\n"
        f"  only in xml: {set(fm_xml.columns) - set(fm_net.columns)}\n"
        f"  only in net: {set(fm_net.columns) - set(fm_xml.columns)}")
    fm_net = fm_net[fm_xml.columns]

    # ── 4. Union, validate, write ───────────────────────────────────────────
    out = pd.concat([fm_xml, fm_net], ignore_index=True)
    n_syn = int((out["is_synthetic"] == 1).sum())
    assert n_syn == 1000, f"ABORT: union synthetic count {n_syn} != 1000"
    assert out["filename"].notna().all(), "ABORT: null filename in output"
    assert out["is_synthetic"].isin([0, 1]).all(), "ABORT: bad is_synthetic value"

    out.to_csv(OUT_TMP, index=False)
    OUT_TMP.replace(FEATURE_CSV)

    print("\n" + "=" * 60)
    print("  RECONCILED FEATURE MATRIX")
    print("=" * 60)
    print(f"  Total rows   : {len(out):,}")
    print(f"  Synthetic    : {n_syn:,}")
    print(f"  Real         : {len(out) - n_syn:,}")
    print(f"    internetdb : {int(fm_net['filename'].str.startswith('internetdb/').sum()):,}")
    print(f"    diversity  : {int(fm_net['filename'].str.startswith('diversity/').sum()):,}")
    print(f"    xml_logs   : {len(fm_xml) - n_syn:,}")
    print(f"  Columns      : {len(out.columns)}  (lead: {list(out.columns[:3])})")
    print(f"  Written      : {FEATURE_CSV.name}")
    print("=" * 60)


if __name__ == "__main__":
    main()
