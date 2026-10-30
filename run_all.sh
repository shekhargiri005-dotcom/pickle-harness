#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────────────────────────
# run_all.sh  — Orchestrator for the Pickle Scanner–Loader Mismatch Harness
#
# Usage (inside the container):
#   bash run_all.sh
#
# Each stage writes its own output; no stage reads another's input until the
# join stage, which is intentional (observer ‖ scanners, joined at the end).
# ──────────────────────────────────────────────────────────────────────────────

set -euo pipefail

# ── Colour helpers ─────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'; NC='\033[0m'
info()  { echo -e "${CYAN}[run_all]${NC} $*"; }
ok()    { echo -e "${GREEN}[run_all]${NC} $*"; }
fail()  { echo -e "${RED}[run_all]${NC} $*" >&2; exit 1; }

# ── Resolve paths relative to this script ────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

RESULTS_DIR="${SCRIPT_DIR}/results"
mkdir -p "$RESULTS_DIR"

# ── Stage 0: Environment fingerprint + polyglot offset ───────────────────────
info "Stage 0/4  Environment fingerprint"
python - <<'PYEOF' | tee "${RESULTS_DIR}/env_fingerprint.txt"
import sys, importlib.metadata, pickle, struct

def ver(pkg):
    try:    return importlib.metadata.version(pkg)
    except: return "not-installed"

# ── Tool versions ────────────────────────────────────────────────────────────
print("=" * 60)
print("  Harness Environment Fingerprint")
print("=" * 60)
print(f"  Python            : {sys.version.split()[0]}  ({sys.executable})")
print(f"  picklescan        : {ver('picklescan')}")
print(f"  modelscan         : {ver('modelscan')}")
print(f"  safetensors       : {ver('safetensors')}")
print(f"  numpy             : {ver('numpy')}")
print(f"  py7zr             : {ver('py7zr')}")
print(f"  pandas            : {ver('pandas')}")
try:
    import torch
    print(f"  torch             : {torch.__version__}  (CPU-only build)")
except ImportError:
    print(f"  torch             : not-installed")

# ── Compute polyglot offset k ────────────────────────────────────────────────
# k = number of bytes in the malicious pickle prefix that precedes the 7z
# archive in each nullifai_7z file.  Computed from the actual exec payload.
# We use a representative marker (file index 1, 4-digit zero-padded).

class _ReduceBasicPayload:
    def __init__(self, marker): self._marker = marker
    def __reduce__(self):
        return (exec, (f"open('{self._marker}', 'w').close()",))

SAMPLE_MARKER = "/tmp/pwned_mal_nullifai_0001"
pickle_prefix = pickle.dumps(_ReduceBasicPayload(SAMPLE_MARKER), protocol=4)
k = len(pickle_prefix)

# 7z magic bytes (first 6 bytes of a valid 7z archive header)
SEVENZ_MAGIC = b"7z\xbc\xaf\x27\x1c"

print()
print(f"  Polyglot offset k : {k} bytes  (len of malicious pickle prefix)")
print(f"  Marker used       : {SAMPLE_MARKER}")
print(f"  Pickle prefix hex : {pickle_prefix.hex()}")
print(f"  7z magic bytes    : {SEVENZ_MAGIC.hex()}  (found at byte {k} of polyglot file)")
print()
print("  Note: k varies slightly per file because marker lengths differ.")
print("  For nullifai_{i:04d}: k = len(pickle.dumps(_ReduceBasicPayload(marker), protocol=4))")
print("  Typical range: 74 – 80 bytes (depending on marker string length).")
print("=" * 60)
PYEOF
ok "Fingerprint written → ${RESULTS_DIR}/env_fingerprint.txt"


info "Stage 1/4  gen_corpus.py"
python gen_corpus.py || fail "gen_corpus.py failed"
ok "Corpus generated."

# ── Stage 2a: Observe loads (ground truth) ────────────────────────────────────
info "Stage 2a/4  observe_load.py"
python observe_load.py || fail "observe_load.py failed"
ok "Load log written."

# ── Stage 2b: Run scanners (independent of loader) ───────────────────────────
info "Stage 2b/4  run_scanners.py"
python run_scanners.py || fail "run_scanners.py failed"
ok "Scan log written."

# ── Stage 3: Join + metrics ───────────────────────────────────────────────────
info "Stage 3/4  join_results.py"
python join_results.py || fail "join_results.py failed"
ok "Results written to ${RESULTS_DIR}/"

# ── Done ──────────────────────────────────────────────────────────────────────
ok "Pipeline complete.  See results/results.csv and results/summary.txt"
