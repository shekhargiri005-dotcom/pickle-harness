# Pickle Scanner–Loader Mismatch Evaluation Harness

> **Purpose:** Measure, per pickle scanner, how many malicious pickle files it
> **fails** to flag that actually **execute** at load time — the
> scanner–loader mismatch — plus false-positive rate on benign files, with
> reproducible, version-stamped results.

---

## ⚠️ Isolation Warning

**This harness loads intentionally malicious pickle files.**  
Every load happens inside a Docker container that is **started with
`--network none`** so payloads cannot make outbound connections.
Each file is loaded in a **fresh subprocess with a hard timeout** (default 10 s).

> **Never run `observe_load.py` (or `run_all.sh`) outside the container or
> with network access.**  The script will refuse to run if it detects a
> reachable egress route, but defence-in-depth requires the Docker
> `--network none` flag.

---

## Repository Layout

```
.
├── Dockerfile
├── README.md
├── requirements.txt
├── run_all.sh              # Orchestrator — run this inside the container
│
├── gen_corpus.py           # Phase 2 — generate corpus + manifest.json
├── observe_load.py         # Phase 3 — ground-truth loader (must run in container)
├── run_scanners.py         # Phase 4 — picklescan + modelscan runner
├── join_results.py         # Phase 5 — hash-join, metrics, summary
│
├── corpus/                 # Created by gen_corpus.py
│   ├── malicious/
│   └── benign/
│
└── results/                # Created by run_all.sh
    ├── manifest.json
    ├── load_log.json
    ├── scan_log.json
    ├── results.csv
    └── summary.txt
```

---

## Exact Reproduction Steps

### 1. Prerequisites

- Docker Engine installed (tested on Docker 24+)
- No other requirements on the host

### 2. Clone / copy the project

```bash
git clone <your-repo-url> pickle-harness
cd pickle-harness
```

### 3. Build the image

```bash
docker build -t pickle-harness:latest .
```

> `pip install` happens here (network allowed at build time).

### 4. Run the full pipeline — **network isolated**

```bash
docker run --rm \
    --network none \
    -v "$(pwd)/results:/harness/results" \
    pickle-harness:latest
```

Outputs are mounted back to `./results/` on your host.

### 5. Inspect results

```
results/manifest.json   — corpus metadata (id → path, is_malicious, variant, …)
results/load_log.json   — did each file execute? (ground truth)
results/scan_log.json   — did each scanner flag it?
results/results.csv     — one row per file, all signals joined
results/summary.txt     — per-scanner detection rate, FP rate, Wilson 95% CI,
                           executed-but-not-flagged counts, version stamp
```

The final table is also **printed to stdout** during the run.

---

## Reproducibility Knobs

| Parameter | Where set | Default |
|-----------|-----------|---------|
| Random seed | `gen_corpus.py` top of file | `42` |
| Loader timeout (s) | `observe_load.py` top of file | `10` |
| Corpus size | `gen_corpus.py` constants | see file |

Re-running with the same seed produces an **identical corpus** and therefore
identical `manifest.json` (same `id` values, same file bytes, same sha256).

---

## Corpus Variants (enum — fixed)

| Variant | Description |
|---------|-------------|
| `reduce_basic` | Classic `__reduce__` payload |
| `nullifai_7z` | Payload at front of stream, 7z-wrapped, corrupted tail |
| `loadpath_trick` | `sys.path` manipulation before the marker write |
| `benign` | Legitimate pickle (dict / list / string payloads) |
| `safetensors_control` | Non-pickle negative control (safetensors format) |

---

## Output Schema

### `manifest.json`
```json
{
  "mal_reduce_001": {
    "id": "mal_reduce_001",
    "path": "corpus/malicious/mal_reduce_001.pkl",
    "is_malicious": true,
    "variant": "reduce_basic",
    "marker": "/tmp/pwned_mal_reduce_001",
    "expected_execution": true
  }
}
```

### `load_log.json`
```json
[
  { "id": "mal_reduce_001", "executed": true,  "state": "loaded"  },
  { "id": "mal_reduce_002", "executed": false, "state": "error"   },
  { "id": "mal_reduce_003", "executed": false, "state": "timeout" }
]
```

### `scan_log.json`
```json
[
  { "id": "mal_reduce_001", "scanner": "picklescan", "result": "flagged" },
  { "id": "mal_reduce_001", "scanner": "modelscan",  "result": "clean"   }
]
```

### `results.csv` columns
`id, variant, is_malicious, executed, picklescan_result, modelscan_result`

---

## Scanner Versions (pinned in `requirements.txt`)

| Scanner | Version |
|---------|---------|
| picklescan | 0.0.22 |
| modelscan | 0.8.4 |

---

## Stack

Python 3.11 · picklescan · modelscan · py7zr · pandas · tabulate · safetensors  
All stdlib for: `pickle`, `pickletools`, `json`, `csv`, `math`, `subprocess`

---

## Security Notes

- Payloads write **only** to a local `/tmp/pwned_<id>` marker file.  
- No reverse shells. No outbound calls. No destructive filesystem operations.  
- The harness is a **measurement tool**, not a defense tool.
