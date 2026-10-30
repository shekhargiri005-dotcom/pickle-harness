#!/usr/bin/env python3
"""
observe_load.py  —  Phase 3: Loader Observer (Ground Truth)

Determines, per corpus file, whether the payload ACTUALLY EXECUTED
(i.e., wrote its marker to /tmp/pwned_<id>) when loaded via Python's
standard pickle machinery.

SAFETY GUARDS — checked before touching ANY file (orchestrator only):
  1. Network egress: refuses if 8.8.8.8:53 is reachable within 2 s.
  2. Container:      refuses if /.dockerenv is absent AND /proc/1/cgroup
                     contains no known container markers.

Execution model:
  • Orchestrator reads manifest.json, iterates all file entries (skips _meta).
  • For each file:
      - Clears marker (if any) so prior-run residue cannot pollute.
      - Spawns THIS SAME FILE as a fresh subprocess with --worker flag.
      - Waits up to TIMEOUT_S seconds.
      - Checks whether the marker file now exists (ground truth = executed).
      - Records {id, executed, state}.
  • Writes results/load_log.json (list, never mutated by other stages).

Worker mode (--worker):
  • Loads one file; exits 0 on success, 1 on exception.
  • Marker writing (for malicious variants) is a payload side-effect.
  • Does NOT re-run safety guards (already inside the container).

Variant loading notes:
  reduce_basic     → pickle.load(fh)          plain pickle
  nullifai_7z      → pickle.load(fh)          pickle bytes at byte-0;
                                               trailing 7z + tail silently
                                               ignored by pickle machinery
  loadpath_trick   → pickle.load(fh)          pickle with eval() wrapper
  benign           → pickle.load(fh)          legitimate data pickle
  safetensors_control → safetensors.numpy.load_file()  non-pickle loader

ASSUMPTION: CWD is /harness (container WORKDIR); paths in manifest are relative.
ASSUMPTION: /tmp/ is writable for marker files.
ASSUMPTION: subprocess.TimeoutExpired is the correct exception for timeout.  (stdlib)
"""

import argparse
import json
import os
import pathlib
import pickle
import socket
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

# ── Config ────────────────────────────────────────────────────────────────────
TIMEOUT_S     = 30   # hard per-file subprocess timeout (seconds) — pickle.load only

# Parallel subprocess workers for the observe phase.
# Each worker slot holds one child process; we wait on I/O, not CPU, so
# threading is appropriate.  Tune down on memory-constrained machines.
N_WORKERS     = 16

MANIFEST_PATH = pathlib.Path("results/manifest.json")
LOAD_LOG_PATH = pathlib.Path("results/load_log.json")

# Variant strings (must match gen_corpus.py exactly)
_PICKLE_VARIANTS      = {"reduce_basic", "nullifai_7z", "loadpath_trick", "benign"}
_SAFETENSORS_VARIANT  = "safetensors_control"

# State enum (three states per spec — do NOT conflate error with timeout)
_STATE_LOADED  = "loaded"
_STATE_ERROR   = "error"
_STATE_TIMEOUT = "timeout"


# ══════════════════════════════════════════════════════════════════════════════
# SAFETY GUARDS
# ══════════════════════════════════════════════════════════════════════════════

def _guard_no_egress() -> None:
    """
    Abort if a network egress route is reachable.
    Attempts TCP connect to 8.8.8.8:53 with a 2-second timeout.
    Under --network none this will always raise OSError / timeout.
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2.0)
        sock.connect(("8.8.8.8", 53))
        sock.close()
        # If we reach here, egress exists → hard abort
        print(
            "[observe_load] ABORT: Network egress detected "
            "(8.8.8.8:53 reachable).\n"
            "[observe_load]   Restart the container with --network none.\n"
            "[observe_load]   Loading malicious pickles with network "
            "access is UNSAFE."
        )
        sys.exit(1)
    except (socket.timeout, OSError):
        pass  # Good — no route to host


def _guard_in_container() -> None:
    """
    Abort if we are not running inside a Linux container.

    Detection heuristics (either is sufficient):
      • /.dockerenv exists           (set by Docker runtime)
      • /proc/1/cgroup contains one of: docker, kubepod, containerd, lxc

    This is a belt-and-suspenders check; --network none is the primary
    isolation mechanism.
    """
    dockerenv = pathlib.Path("/.dockerenv")
    cgroup    = pathlib.Path("/proc/1/cgroup")

    in_container: bool = dockerenv.exists()

    if not in_container and cgroup.exists():
        try:
            text = cgroup.read_text(errors="replace")
            in_container = any(
                marker in text
                for marker in ("docker", "kubepod", "containerd", "lxc")
            )
        except OSError:
            pass  # /proc/1/cgroup unreadable — assume not in container

    if not in_container:
        print(
            "[observe_load] ABORT: Not running inside a container.\n"
            "[observe_load]   /.dockerenv absent AND /proc/1/cgroup has "
            "no container markers.\n"
            "[observe_load]   This script loads MALICIOUS PICKLE FILES.\n"
            "[observe_load]   Use:  docker run --network none <image>"
        )
        sys.exit(1)


# ══════════════════════════════════════════════════════════════════════════════
# WORKER  (runs in a fresh subprocess per file; no guards re-run here)
# ══════════════════════════════════════════════════════════════════════════════

def _worker_main(path: str, variant: str, marker: str | None) -> None:
    """
    Subprocess worker: runs ONLY the dangerous pickle.load() path.

    torch.load(weights_only=True) and safetensors checks are run in-process
    by the orchestrator — both are safe by design (they block/reject rather
    than enable execution) and do NOT require subprocess isolation.

    Emits a single JSON line to stdout:
      {"executed": bool, "state": "loaded"|"error"}

    nullifai_7z: pickle bytes at byte-0; pickle.load() halts at STOP opcode;
    trailing 7z bytes + corrupted tail are never read.
    """
    p        = pathlib.Path(path)
    marker_p = pathlib.Path(marker) if marker else None

    if marker_p:
        marker_p.unlink(missing_ok=True)  # clear any prior residue

    state = _STATE_ERROR
    try:
        if variant == _SAFETENSORS_VARIANT:
            from safetensors.numpy import load_file as _st_load
            _st_load(str(p))
        elif variant in _PICKLE_VARIANTS:
            with open(p, "rb") as fh:
                pickle.load(fh)   # payload side-effects (marker write) happen here
        else:
            print(f"[worker] unknown variant '{variant}'", file=sys.stderr)
            sys.exit(1)
        state = _STATE_LOADED
    except Exception as exc:
        print(f"[worker] pickle load ({variant}): {exc}", file=sys.stderr)
        state = _STATE_ERROR

    executed = bool(marker_p and marker_p.exists())
    print(json.dumps({"executed": executed, "state": state}), flush=True)
    sys.exit(0)


# ══════════════════════════════════════════════════════════════════════════════
# ORCHESTRATOR
# ══════════════════════════════════════════════════════════════════════════════

def _load_one_file(
    idx: int,
    fid: str,
    entry: dict,
    total: int,
) -> dict:
    """
    Three-mode execution test for one corpus file.

    Mode 1 (pickle.load) — runs in a fresh SUBPROCESS for isolation:
      The payload's side-effect (marker write) happens here.
      Subprocess isolation means a crashed/hung payload cannot corrupt
      the orchestrator state.

    Mode 2 (torch.load weights_only=True) — runs IN-PROCESS in orchestrator:
      RestrictedUnpickler raises before any code runs.  Safe to run in-process
      because the defense is structural (allowlist enforced before execution).
      Running in-process avoids the 10+ second torch import penalty per file.

    Mode 3 (safetensors.load_file) — runs IN-PROCESS in orchestrator:
      Format barrier: safetensors header parser rejects pickle bytes immediately.
      No Python unpickler is invoked.  Safe to run in-process.
    """
    path    : str        = entry["path"]
    variant : str        = entry["variant"]
    marker  : str | None = entry.get("marker")
    marker_p = pathlib.Path(marker) if marker else None

    # ── Mode 1: subprocess pickle.load() ──────────────────────────────────────
    cmd = [
        sys.executable, __file__,
        "--worker",
        "--path",    path,
        "--variant", variant,
    ]
    if marker:
        cmd += ["--marker", marker]

    pkl_executed = False
    pkl_state    = _STATE_ERROR
    t0 = time.monotonic()

    try:
        proc = subprocess.run(cmd, timeout=TIMEOUT_S, capture_output=True)
        elapsed = time.monotonic() - t0

        raw = (proc.stdout or b"").decode(errors="replace").strip()
        if raw:
            try:
                wdata = json.loads(raw)
                pkl_executed = wdata.get("executed", False)
                pkl_state    = wdata.get("state", _STATE_ERROR)
            except json.JSONDecodeError:
                pass

        if proc.returncode != 0 and proc.stderr:
            snip = proc.stderr.decode(errors="replace").strip()
            if snip:
                print(f"[observe_load]   stderr [{fid}]: {snip[:200]}")

    except subprocess.TimeoutExpired:
        elapsed = float(TIMEOUT_S)
        pkl_state = _STATE_TIMEOUT
        # Check marker — payload may have executed before hang
        pkl_executed = bool(marker_p and marker_p.exists())

    # ── Mode 2: torch.load(weights_only=True) — in-process ───────────────────
    # Clear marker so we can test if this mode also executes the payload
    if marker_p:
        marker_p.unlink(missing_ok=True)
    wo_executed = False
    wo_state    = _STATE_ERROR
    try:
        import torch as _torch
        _torch.load(path, weights_only=True, map_location="cpu")
        wo_state = _STATE_LOADED
    except Exception:
        wo_state = _STATE_ERROR   # expected for malicious files
    wo_executed = bool(marker_p and marker_p.exists())

    # ── Mode 3: safetensors.load_file — in-process ────────────────────────────
    if marker_p:
        marker_p.unlink(missing_ok=True)
    st_executed = False
    st_state    = _STATE_ERROR
    try:
        from safetensors.numpy import load_file as _st_lf
        _st_lf(path)
        st_state = _STATE_LOADED
    except Exception:
        st_state = _STATE_ERROR   # expected for pickle files
    st_executed = bool(marker_p and marker_p.exists())

    if marker_p:
        marker_p.unlink(missing_ok=True)  # clean up

    exec_tag = "EXEC  " if pkl_executed else "      "
    print(
        f"[observe_load]  [{idx:5d}/{total}]  {exec_tag}"
        f"pkl={str(pkl_executed)[0]}  wo={str(wo_executed)[0]}  "
        f"st={str(st_executed)[0]}  t={elapsed:.1f}s  {fid}"
    )

    return {
        "id":                    fid,
        "executed_pickle":       pkl_executed,
        "state_pickle":          pkl_state,
        "executed_weights_only": wo_executed,
        "state_weights_only":    wo_state,
        "executed_safetensors":  st_executed,
        "state_safetensors":     st_state,
    }


def _orchestrator_main() -> None:
    """
    Iterate manifest, spawn N_WORKERS fresh subprocesses in parallel,
    record results.  Writes results/load_log.json.
    """
    # 1. Safety guards — must be first, before any file I/O on corpus
    _guard_no_egress()
    _guard_in_container()

    # 2. Load manifest
    if not MANIFEST_PATH.exists():
        print(
            f"[observe_load] ERROR: {MANIFEST_PATH} not found.\n"
            f"[observe_load]   Run gen_corpus.py first."
        )
        sys.exit(1)

    full_manifest: dict = json.loads(MANIFEST_PATH.read_text())
    entries: dict = {
        k: v for k, v in full_manifest.items() if not k.startswith("_")
    }

    total = len(entries)
    print(
        f"[observe_load] {total} files to load  |  "
        f"timeout={TIMEOUT_S}s per file  |  workers={N_WORKERS}"
    )
    print(f"[observe_load] Guards passed: no egress, inside container.")
    print()

    # 3. Dispatch all files via thread pool (each thread manages one subprocess)
    log: list[dict] = []
    items = list(entries.items())

    with ThreadPoolExecutor(max_workers=N_WORKERS) as pool:
        future_to_fid = {
            pool.submit(_load_one_file, idx, fid, entry, total): fid
            for idx, (fid, entry) in enumerate(items, start=1)
        }
        for future in as_completed(future_to_fid):
            exc = future.exception()
            if exc:
                fid = future_to_fid[future]
                print(f"[observe_load] ERROR: future for {fid} raised {exc}")
                log.append({
                    "id": fid,
                    "executed_pickle": False,       "state_pickle":          _STATE_ERROR,
                    "executed_weights_only": False, "state_weights_only":    _STATE_ERROR,
                    "executed_safetensors":  False, "state_safetensors":     _STATE_ERROR,
                })
            else:
                log.append(future.result())

    # Re-sort to match manifest order (as_completed is non-deterministic)
    id_order = {fid: i for i, (fid, _) in enumerate(items)}
    log.sort(key=lambda e: id_order.get(e["id"], 999999))

    # 4. Write load_log.json
    LOAD_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    LOAD_LOG_PATH.write_text(json.dumps(log, indent=2))

    # 5. Summary
    n_exec_pkl = sum(1 for e in log if e.get("executed_pickle"))
    n_exec_wo  = sum(1 for e in log if e.get("executed_weights_only"))
    n_exec_st  = sum(1 for e in log if e.get("executed_safetensors"))
    n_loaded   = sum(1 for e in log if e.get("state_pickle") == _STATE_LOADED)
    n_error    = sum(1 for e in log if e.get("state_pickle") == _STATE_ERROR)
    n_timeout  = sum(1 for e in log if e.get("state_pickle") == _STATE_TIMEOUT)

    print()
    print(f"[observe_load] ── Load log complete ──────────────────────────────")
    print(f"[observe_load]  Total files       : {total}")
    print(f"[observe_load]  Executed (pickle) : {n_exec_pkl}   (marker written)")
    print(f"[observe_load]  Executed (wo=True): {n_exec_wo}   (should be 0 — defense)")
    print(f"[observe_load]  Executed (sftnsrs): {n_exec_st}   (should be 0 — defense)")
    print(f"[observe_load]  State=loaded      : {n_loaded}")
    print(f"[observe_load]  State=error       : {n_error}")
    print(f"[observe_load]  State=timeout     : {n_timeout}")
    print(f"[observe_load]  Log path          : {LOAD_LOG_PATH}")
    print(f"[observe_load] ───────────────────────────────────────────────")


# ══════════════════════════════════════════════════════════════════════════════
# ENTRYPOINT
# ══════════════════════════════════════════════════════════════════════════════

def main() -> None:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--worker",  action="store_true",
                        help="Run in worker mode (load one file; no guards).")
    parser.add_argument("--path",    default=None,
                        help="Path to the file to load (worker mode only).")
    parser.add_argument("--variant", default=None,
                        help="Variant string (worker mode only).")
    parser.add_argument("--marker",  default=None,
                        help="Marker file path for mechanism elimination tracking "
                             "(worker mode only; None for benign files).")
    args, _ = parser.parse_known_args()

    if args.worker:
        if not args.path or not args.variant:
            print(
                "[worker] --path and --variant are required in worker mode.",
                file=sys.stderr,
            )
            sys.exit(1)
        _worker_main(args.path, args.variant, args.marker)
    else:
        _orchestrator_main()


if __name__ == "__main__":
    main()
