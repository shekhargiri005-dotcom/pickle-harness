#!/usr/bin/env python3
"""
join_results.py  —  Phase 5: Join + Metrics

Hash-joins manifest.json + load_log.json + scan_log.json on `id`.
Computes per-scanner confusion-matrix metrics in a single pass per scanner.
Writes results/results.csv and results/summary.txt; prints final table.

Complexity guarantees (per spec):
  • Join:    O(n) time, O(n) space  — three dict builds + one pass over manifest.
  • Metrics: O(n) per scanner       — single confusion-matrix fold, no nested scan.
  n = corpus file count (≤ 60).

pandas:   used ONLY here (join stage), for DataFrame construction + CSV write.
tabulate: printed table.
math:     Wilson 95% CI — no scipy.

CSV columns (spec-exact key names):
  id, variant, is_malicious, executed, picklescan_result, modelscan_result

load_log.json key  "executed": bool   — ground truth (did payload run?).
scan_log.json key  "result": flagged|clean|error.

Detection rate denominator = files where executed=True  (mismatch ground truth).
FP rate denominator        = files where is_malicious=False (all benign files).
executed_but_not_flagged   = executed=True AND scanner_result ≠ "flagged".
"""

import datetime
import importlib.metadata
import json
import math
import pathlib
import sys

import pandas as pd
from tabulate import tabulate

# ── Paths ─────────────────────────────────────────────────────────────────────
MANIFEST_PATH = pathlib.Path("results/manifest.json")
LOAD_LOG_PATH = pathlib.Path("results/load_log.json")
SCAN_LOG_PATH = pathlib.Path("results/scan_log.json")
RESULTS_CSV   = pathlib.Path("results/results.csv")
SUMMARY_PATH  = pathlib.Path("results/summary.txt")

# Scanner names — must match run_scanners.py exactly
_S_PICKLESCAN  = "picklescan"
_S_MODELSCAN   = "modelscan"
_SCANNER_NAMES = [_S_PICKLESCAN, _S_MODELSCAN]

# Column names in the joined rows for each scanner's result
_COL_MAP = {
    _S_PICKLESCAN: "picklescan_result",
    _S_MODELSCAN:  "modelscan_result",
}

# Variant enum — order matters for display
_VARIANTS_MAL = ["reduce_basic", "nullifai_7z", "loadpath_trick"]
_VARIANTS_BEN = ["benign", "safetensors_control"]
_ALL_VARIANTS = _VARIANTS_MAL + _VARIANTS_BEN

# Wilson z for 95% CI  (z_{0.025} = 1.959964...)
_Z95 = 1.959964


# ══════════════════════════════════════════════════════════════════════════════
# WILSON 95% CONFIDENCE INTERVAL  (stdlib math only)
# ══════════════════════════════════════════════════════════════════════════════

def wilson_ci(k: int, n: int) -> tuple[float, float]:
    """
    Wilson score interval for proportion k/n at 95% confidence.
    Returns (lower, upper) clamped to [0, 1].

    Formula (confirmed source: statisticsfundamentals.com / Wikipedia):

        denominator = 1 + z² / n
        center      = p̂ + z² / (2n)
        std_adj     = sqrt( (p̂(1-p̂) + z²/(4n)) / n )

        lower = (center - z * std_adj) / denominator
        upper = (center + z * std_adj) / denominator

    where p̂ = k / n.

    Special cases:
      n = 0 → (nan, nan)
      k = 0 → lower bound is 0 (formula handles this naturally)
      k = n → upper bound is 1 (clamped)
    """
    if n == 0:
        return (float("nan"), float("nan"))

    p    = k / n
    z    = _Z95
    z2   = z * z
    n_f  = float(n)

    denominator = 1.0 + z2 / n_f
    center      = p + z2 / (2.0 * n_f)
    std_adj     = math.sqrt((p * (1.0 - p) + z2 / (4.0 * n_f)) / n_f)

    lower = (center - z * std_adj) / denominator
    upper = (center + z * std_adj) / denominator

    return (max(0.0, lower), min(1.0, upper))


# ══════════════════════════════════════════════════════════════════════════════
# METRICS  (single pass over rows)
# ══════════════════════════════════════════════════════════════════════════════

def compute_metrics(
    rows: list[dict],
    scanner_col: str,
    exec_col: str = "executed_pickle",
) -> dict:
    """
    One confusion-matrix fold for one scanner over the given row subset.

    exec_col selects which executed_* field drives the detection-rate
    denominator.  Default = 'executed_pickle' (standard pickle.load baseline).

    Counts in a single pass (O(n)):
      tp: exec_col=True  AND result="flagged"
      fn: exec_col=True  AND result≠"flagged"   ← scanner missed executing payload
      fp: is_malicious=False AND result="flagged"
      tn: is_malicious=False AND result≠"flagged"

    Note: fn IS the executed_but_not_flagged count (scanner–loader mismatch).
    """
    tp = fn = fp = tn = 0

    for row in rows:
        result   = row[scanner_col]          # "flagged" | "clean" | "error"
        executed = row.get(exec_col, False)   # bool — use .get() for backward compat
        is_mal   = row["is_malicious"]        # bool

        if executed:
            if result == "flagged":
                tp += 1
            else:
                fn += 1

        if not is_mal:
            if result == "flagged":
                fp += 1
            else:
                tn += 1

    n_exec   = tp + fn
    n_benign = fp + tn

    det_rate = tp / n_exec   if n_exec   > 0 else float("nan")
    fp_rate  = fp / n_benign if n_benign > 0 else float("nan")
    ci_lo, ci_hi = wilson_ci(tp, n_exec)

    return {
        "tp":                       tp,
        "fn":                       fn,
        "fp":                       fp,
        "tn":                       tn,
        "n_executed":               n_exec,
        "n_benign":                 n_benign,
        "detection_rate":           det_rate,
        "ci_low":                   ci_lo,
        "ci_high":                  ci_hi,
        "fp_rate":                  fp_rate,
        "executed_but_not_flagged": fn,
    }


def per_variant_metrics(
    rows: list[dict],
    scanner_col: str,
) -> dict[str, dict | None]:
    """
    Compute metrics for each variant in _ALL_VARIANTS.
    Returns {variant: metrics_dict} or {variant: None} if variant absent.
    """
    result: dict = {}
    for variant in _ALL_VARIANTS:
        subset = [r for r in rows if r["variant"] == variant]
        result[variant] = compute_metrics(subset, scanner_col) if subset else None
    return result


# ══════════════════════════════════════════════════════════════════════════════
# HELPERS
# ══════════════════════════════════════════════════════════════════════════════

def _pkg_version(pkg: str) -> str:
    """Return installed package version, or 'unknown' if not found."""
    try:
        return importlib.metadata.version(pkg)
    except importlib.metadata.PackageNotFoundError:
        return "unknown"


def _pct(v: float, width: int = 5) -> str:
    """Format a [0,1] float as a percentage string. NaN → 'N/A'."""
    return "N/A" if math.isnan(v) else f"{v * 100:{width}.1f}%"


def _ci_str(lo: float, hi: float) -> str:
    """Format Wilson CI as '[lo%, hi%]'. NaN → '[N/A]'."""
    if math.isnan(lo) or math.isnan(hi):
        return "[N/A]"
    return f"[{lo * 100:.1f}%, {hi * 100:.1f}%]"


# ══════════════════════════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════════════════════════

def main() -> None:

    # ── Step 1: Validate inputs exist ─────────────────────────────────────────
    for p in (MANIFEST_PATH, LOAD_LOG_PATH, SCAN_LOG_PATH):
        if not p.exists():
            print(
                f"[join_results] ERROR: {p} not found — run earlier stages first.",
                file=sys.stderr,
            )
            sys.exit(1)

    # ── Step 2: Load raw JSON ─────────────────────────────────────────────────
    full_manifest: dict = json.loads(MANIFEST_PATH.read_text())
    load_log:      list = json.loads(LOAD_LOG_PATH.read_text())
    scan_log:      list = json.loads(SCAN_LOG_PATH.read_text())

    meta: dict = full_manifest.get("_meta", {})

    # ── Step 3: Build O(1) lookup dicts ──────────────────────────────────────
    # manifest: already keyed by id (skip _meta)
    manifest: dict = {
        k: v for k, v in full_manifest.items() if not k.startswith("_")
    }

    # load_log: list → dict keyed by id
    load_lookup: dict = {e["id"]: e for e in load_log}

    # scan_log: long → wide pivot  {id: {scanner_name: result}}
    # Single pass; O(n × scanners)
    scan_pivot: dict = {}
    for entry in scan_log:
        fid = entry["id"]
        if fid not in scan_pivot:
            scan_pivot[fid] = {}
        scan_pivot[fid][entry["scanner"]] = entry["result"]

    # ── Step 4: Hash-join (single pass over manifest) — O(n) ─────────────────
    rows: list[dict] = []
    warn_load: list  = []
    warn_scan: list  = []

    for fid, m in manifest.items():
        l = load_lookup.get(fid)
        s = scan_pivot.get(fid, {})

        if l is None:
            warn_load.append(fid)
            l = {}

        if not s:
            warn_scan.append(fid)

        # Backward-compat: old load_log had "executed" (bool); new has "executed_pickle".
        executed_pickle = l.get("executed_pickle", l.get("executed", False))

        rows.append({
            "id":                    fid,
            "variant":               m["variant"],
            "is_malicious":          m["is_malicious"],
            "callable_used":         m.get("callable_used"),
            "executed_pickle":       executed_pickle,
            "executed_weights_only": l.get("executed_weights_only", False),
            "executed_safetensors":  l.get("executed_safetensors",  False),
            "picklescan_result":     s.get(_S_PICKLESCAN, "error"),
            "modelscan_result":      s.get(_S_MODELSCAN,  "error"),
        })

    if warn_load:
        print(
            f"[join_results] WARNING: {len(warn_load)} id(s) missing from "
            f"load_log — treated as executed=False: {warn_load[:5]}"
        )
    if warn_scan:
        print(
            f"[join_results] WARNING: {len(warn_scan)} id(s) missing from "
            f"scan_log — treated as error: {warn_scan[:5]}"
        )

    # ── Step 5: Write results.csv (pandas for CSV; join already done) ─────────
    RESULTS_CSV.parent.mkdir(parents=True, exist_ok=True)
    df = pd.DataFrame(rows)
    col_order = [
        "id", "variant", "is_malicious", "callable_used",
        "executed_pickle", "executed_weights_only", "executed_safetensors",
        "picklescan_result", "modelscan_result",
    ]
    df = df[col_order]
    df.to_csv(RESULTS_CSV, index=False)
    print(f"[join_results] results.csv  → {RESULTS_CSV}  ({len(df)} rows)")

    # ── Step 6: Compute per-scanner overall + per-variant metrics ─────────────
    # One pass per scanner (O(n) each)
    overall: dict[str, dict]            = {}
    by_var:  dict[str, dict[str, dict]] = {}

    for scanner in _SCANNER_NAMES:
        col = _COL_MAP[scanner]
        overall[scanner] = compute_metrics(rows, col, exec_col="executed_pickle")
        by_var[scanner]  = per_variant_metrics(rows, col)

    # ── Step 7: Build tabulate tables ─────────────────────────────────────────

    # Table A — overall per-scanner summary
    tbl_A_rows = []
    for scanner in _SCANNER_NAMES:
        m = overall[scanner]
        tbl_A_rows.append([
            scanner,
            _pct(m["detection_rate"]),
            _ci_str(m["ci_low"], m["ci_high"]),
            _pct(m["fp_rate"]),
            m["executed_but_not_flagged"],
            f"{m['tp']}/{m['n_executed']}",
        ])

    table_A = tabulate(
        tbl_A_rows,
        headers=[
            "Scanner",
            "Det Rate",
            "Wilson 95% CI",
            "FP Rate",
            "Exec-Not-Flagged",
            "TP/N_exec",
        ],
        tablefmt="github",
    )

    # Table B — per-variant breakdown (malicious variants only for det rate;
    #           benign variants for FP rate)
    tbl_B_rows = []
    for scanner in _SCANNER_NAMES:
        for variant in _ALL_VARIANTS:
            m = by_var[scanner].get(variant)
            if m is None:
                continue
            is_mal_variant = variant in _VARIANTS_MAL
            tbl_B_rows.append([
                scanner,
                variant,
                "MAL" if is_mal_variant else "BEN",
                m["n_executed"]    if is_mal_variant else "-",
                m["executed_but_not_flagged"] if is_mal_variant else "-",
                _pct(m["detection_rate"]) if is_mal_variant else "-",
                m["fp"]            if not is_mal_variant else "-",
                _pct(m["fp_rate"]) if not is_mal_variant else "-",
            ])

    table_B = tabulate(
        tbl_B_rows,
        headers=[
            "Scanner",
            "Variant",
            "Type",
            "N Exec",
            "Exec-Not-Flag",
            "Det Rate",
            "FP Count",
            "FP Rate",
        ],
        tablefmt="github",
    )

    # ── Step 8: Build run-stamp block ─────────────────────────────────────────
    stamp = "\n".join([
        f"Timestamp     : {datetime.datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')}",
        f"Seed          : {meta.get('seed', 'N/A')}",
        f"Corpus sha256 : {meta.get('corpus_sha256', 'N/A')}",
        f"Total files   : {meta.get('total_files', len(manifest))}",
        f"  n_malicious : {meta.get('n_malicious', '?')}",
        f"  n_benign    : {meta.get('n_benign', '?')}",
        f"picklescan    : {_pkg_version('picklescan')}",
        f"modelscan     : {_pkg_version('modelscan')}",
        f"python        : {sys.version.split()[0]}",
    ])

    # ── Step 9: Mechanism Elimination Results ─────────────────────────────────
    mal_rows    = [r for r in rows if r["is_malicious"]]
    n_mal_total = len(mal_rows)
    n_exec_pkl  = sum(1 for r in mal_rows if r["executed_pickle"])
    n_exec_wo   = sum(1 for r in mal_rows if r["executed_weights_only"])
    n_exec_st   = sum(1 for r in mal_rows if r["executed_safetensors"])

    mech_lines = [
        f"  {'Loader':<36} {'Exec':>5} / {'Total':>5}  {'Notes'}",
        f"  {'-'*36} {'-'*5}   {'-'*5}  {'-'*30}",
        f"  {'Standard pickle.load()':<36} {n_exec_pkl:>5} / {n_mal_total:>5}",
        f"  {'torch.load(weights_only=True)':<36} {n_exec_wo:>5} / {n_mal_total:>5}"
        f"  ← should be 0",
        f"  {'safetensors.numpy.load_file()':<36} {n_exec_st:>5} / {n_mal_total:>5}"
        f"  ← should be 0",
    ]

    # ── Step 10: Payload Callable Summary (for paper methodology section) ─────
    callable_by_variant: dict[str, str] = {}
    for r in rows:
        v = r["variant"]
        c = r.get("callable_used") or "N/A"
        callable_by_variant[v] = c

    callable_lines = [
        f"  {v:<22}: {callable_by_variant.get(v, 'N/A')}"
        for v in (_VARIANTS_MAL + _VARIANTS_BEN)
        if v in callable_by_variant
    ]

    # ── Step 11: Headline scanner mismatch (pickle.load baseline) ────────────
    mismatch_lines = []
    for scanner in _SCANNER_NAMES:
        m = overall[scanner]
        mismatch_lines.append(
            f"  {scanner:<14}: {m['executed_but_not_flagged']:3d} executed payload(s) "
            f"NOT flagged  (out of {m['n_executed']} that executed)"
        )

    summary_text = "\n".join([
        "=" * 72,
        "  Pickle Scanner–Loader Mismatch Evaluation — Results Summary",
        "=" * 72,
        "",
        "── Run Stamp " + "─" * 59,
        stamp,
        "",
        "── Payload Callables (Methodology Section) " + "─" * 29,
        "  Exact GLOBAL opcode callables baked into each pickle variant:",
        *callable_lines,
        "",
        "── Mechanism Elimination Results " + "─" * 38,
        "  Tests whether alternative loaders PREVENT payload execution.",
        "  Denominator = all malicious files (is_malicious=True).",
        *mech_lines,
        "",
        "── Scanner–Loader Mismatch Headline " + "─" * 35,
        "  (executed payloads the scanner FAILED to flag — pickle.load baseline)",
        *mismatch_lines,
        "",
        "── Overall Per-Scanner Metrics " + "─" * 40,
        "  Det Rate  : fraction of EXECUTED malicious files flagged",
        "  FP Rate   : fraction of BENIGN files flagged",
        "  Wilson CI : 95% score interval (stdlib math, no scipy)",
        "",
        table_A,
        "",
        "── Per-Variant Breakdown " + "─" * 47,
        "  MAL rows: detection metrics over executed malicious files",
        "  BEN rows: false-positive metrics over benign files",
        "",
        table_B,
        "",
        "── Variant Key " + "─" * 56,
        "  reduce_basic        : classic __reduce__ → exec()  [callable: builtins.exec]",
        "  nullifai_7z         : polyglot (pickle-front + 7z + tail)  [callable: builtins.exec]",
        "  loadpath_trick      : indirect eval+base64  [GLOBAL=eval; exec hidden in b64]",
        "  benign              : legitimate pickle (no callables, no GLOBAL opcodes)",
        "  safetensors_control : non-pickle negative control (.safetensors format)",
        "",
        "=" * 72,
    ])

    # ── Step 12: Write summary.txt + print to stdout ───────────────────────────
    SUMMARY_PATH.write_text(summary_text)
    print(f"[join_results] summary.txt  → {SUMMARY_PATH}")
    print()
    print(summary_text)


if __name__ == "__main__":
    main()



if __name__ == "__main__":
    main()
