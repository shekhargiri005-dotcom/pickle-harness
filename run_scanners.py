#!/usr/bin/env python3
"""
run_scanners.py  —  Phase 4: Scanner Runner

Runs picklescan and modelscan over every file in the corpus.
Results are recorded independently from observe_load.py; the two outputs
are only joined in join_results.py (Phase 5).

Three result states per scanner per file  (do NOT conflate error with clean):
  "flagged"  — scanner completed and detected a threat
  "clean"    — scanner completed and found nothing
  "error"    — scanner itself failed / crashed / could not process the file

Exit-code mapping (confirmed from pypi docs):

  picklescan  0 = clean   1 = flagged   2 = error
  modelscan   0 = clean   1 = flagged   2 = error (scan threw)
                                        3 = error (no supported files)
                                        4 = error (usage / bad args)

Writes: results/scan_log.json  — list of {id, scanner, result} entries,
        one per (file × scanner) combination, keyed by the same id as
        manifest.json for O(1) join in Phase 5.

ASSUMPTION: CWD is /harness.  Paths in manifest are relative to CWD.
ASSUMPTION: 'picklescan' and 'modelscan' executables are on PATH
            (installed via pip in the container image).
ASSUMPTION: modelscan CLI is invoked as:
              modelscan -p <path>    (not 'modelscan scan -p <path>')
            — confirmed from pypi 0.8.4 docs.  # VERIFY if CLI sub-command
              becomes required in a future version.
"""

import json
import pathlib
import subprocess
import sys
import time

# ── Config ────────────────────────────────────────────────────────────────────
MANIFEST_PATH  = pathlib.Path("results/manifest.json")
SCAN_LOG_PATH  = pathlib.Path("results/scan_log.json")

# Per-scanner subprocess timeout (s) — generous; scanning is static analysis
SCANNER_TIMEOUT_S = 30

# Result enum (spec: "flagged|clean|error")
_R_FLAGGED = "flagged"
_R_CLEAN   = "clean"
_R_ERROR   = "error"

# Scanner name enum (spec: "picklescan|modelscan")
_S_PICKLESCAN = "picklescan"
_S_MODELSCAN  = "modelscan"


# ── Exit-code → result mappers ────────────────────────────────────────────────

def _picklescan_result(returncode: int) -> str:
    """
    picklescan exit codes (ClamAV model, from pypi docs):
      0  clean
      1  flagged (infected files found)
      2  error   (parse / IO failure)
    Any other code is treated as error.
    """
    if returncode == 0:
        return _R_CLEAN
    if returncode == 1:
        return _R_FLAGGED
    return _R_ERROR  # returncode == 2 or anything unexpected


def _modelscan_result(returncode: int) -> str:
    """
    modelscan exit codes (from pypi docs):
      0  clean
      1  flagged (vulnerabilities found)
      2  error   (scan threw an exception)
      3  error   (no supported files)
      4  error   (usage / bad args)
    Any other code is treated as error.
    """
    if returncode == 0:
        return _R_CLEAN
    if returncode == 1:
        return _R_FLAGGED
    # Codes 2, 3, 4, or anything else → error
    return _R_ERROR


# ── Per-file scanner invocation ───────────────────────────────────────────────

def _run_picklescan(file_path: str) -> tuple[str, str, str]:
    """
    Invoke picklescan on a single file.
    Returns: (result, stdout_text, stderr_text)
      result: "flagged" | "clean" | "error"

    Both stdout and stderr are captured so the caller can record the exact
    parse-failure message for nullifai_7z files (paper TODO §IV-B).
    CLI: picklescan --path <file>
    """
    try:
        proc = subprocess.run(
            ["picklescan", "--path", file_path],
            capture_output=True,
            timeout=SCANNER_TIMEOUT_S,
        )
        stdout = proc.stdout.decode(errors="replace").strip()
        stderr = proc.stderr.decode(errors="replace").strip()
        return _picklescan_result(proc.returncode), stdout, stderr
    except subprocess.TimeoutExpired:
        return _R_ERROR, "", "timeout"
    except FileNotFoundError:
        print(
            "[run_scanners] FATAL: 'picklescan' not found on PATH.\n"
            "[run_scanners]   Was it installed?  pip install picklescan==0.0.22",
            file=sys.stderr,
        )
        sys.exit(1)
    except Exception as exc:
        print(f"[run_scanners] picklescan exception on {file_path}: {exc}", file=sys.stderr)
        return _R_ERROR, "", str(exc)


def _run_modelscan(file_path: str) -> str:
    """
    Invoke modelscan on a single file.
    Returns: "flagged" | "clean" | "error"

    CLI: modelscan -p <file>
    Exit code 3 ("no supported files") is mapped to "clean" for safetensors
    files that modelscan doesn't recognise — still not flagged, which matters
    for false-positive rate.  But "error" is more honest; we use "error" so
    the join stage can distinguish "skipped" from "actually clean".

    NOTE: modelscan may not support raw .pkl files by default and may return
    exit code 3 for them.  This is treated as "error" per spec (do not
    conflate with clean).  # VERIFY: whether modelscan 0.8.4 handles bare .pkl
    """
    try:
        proc = subprocess.run(
            ["modelscan", "-p", file_path],
            capture_output=True,
            timeout=SCANNER_TIMEOUT_S,
        )
        return _modelscan_result(proc.returncode)
    except subprocess.TimeoutExpired:
        return _R_ERROR
    except FileNotFoundError:
        print(
            "[run_scanners] FATAL: 'modelscan' not found on PATH.\n"
            "[run_scanners]   Was it installed?  pip install modelscan==0.8.4",
            file=sys.stderr,
        )
        sys.exit(1)
    except Exception as exc:
        print(f"[run_scanners] modelscan exception on {file_path}: {exc}", file=sys.stderr)
        return _R_ERROR


# ── Scanner registry ──────────────────────────────────────────────────────────
# Extend this list to add more scanners; the rest of the pipeline auto-adapts.

_SCANNERS: list[tuple[str, callable]] = [
    (_S_PICKLESCAN, _run_picklescan),
    (_S_MODELSCAN,  _run_modelscan),
]


# ── Main ──────────────────────────────────────────────────────────────────────

def main() -> None:
    # ── Load manifest ─────────────────────────────────────────────────────────
    if not MANIFEST_PATH.exists():
        print(
            f"[run_scanners] ERROR: {MANIFEST_PATH} not found.\n"
            f"[run_scanners]   Run gen_corpus.py first.",
            file=sys.stderr,
        )
        sys.exit(1)

    full_manifest: dict = json.loads(MANIFEST_PATH.read_text())

    # Skip _meta (reserved key; not a file entry)
    entries: dict = {
        k: v for k, v in full_manifest.items() if not k.startswith("_")
    }

    total   = len(entries)
    n_scans = total * len(_SCANNERS)
    print(
        f"[run_scanners] {total} files × {len(_SCANNERS)} scanners "
        f"= {n_scans} scan operations"
    )
    print(
        f"[run_scanners] Scanners: "
        + ", ".join(name for name, _ in _SCANNERS)
    )
    print()

    # Trace file for Picklescan behavior on nullifai_7z (paper TODO §IV-B)
    TRACE_PATH = pathlib.Path("results/picklescan_nullifai_trace.txt")
    traces: list[str] = []

    log: list = []

    for idx, (fid, entry) in enumerate(entries.items(), start=1):
        file_path = entry["path"]
        variant   = entry["variant"]

        for scanner_name, scanner_fn in _SCANNERS:
            t0 = time.monotonic()

            if scanner_name == _S_PICKLESCAN:
                result, ps_stdout, ps_stderr = scanner_fn(file_path)
                # Capture stdout/stderr for nullifai_7z (paper §IV-B TODO)
                if variant == "nullifai_7z":
                    traces.append(
                        f"\n{'─'*60}\n"
                        f"File   : {fid}\n"
                        f"Path   : {file_path}\n"
                        f"Result : {result}\n"
                        f"STDOUT :\n{ps_stdout or '(empty)'}\n"
                        f"STDERR :\n{ps_stderr or '(empty)'}\n"
                    )
            else:
                result = scanner_fn(file_path)

            elapsed = time.monotonic() - t0

            log.append({
                "id":      fid,
                "scanner": scanner_name,
                "result":  result,
            })

            flag_tag = {
                _R_FLAGGED: "FLAG",
                _R_CLEAN:   "    ",
                _R_ERROR:   "ERR ",
            }.get(result, "????")

            print(
                f"[run_scanners]  [{idx:5d}/{total}] "
                f"{flag_tag}  {scanner_name:<14}  "
                f"({elapsed:.1f}s)  {fid}"
            )

    # ── Write scan_log.json ───────────────────────────────────────────────────
    SCAN_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    SCAN_LOG_PATH.write_text(json.dumps(log, indent=2))

    # ── Write Picklescan nullifai_7z trace (paper TODO §IV-B) ────────────────
    if traces:
        header = (
            "Picklescan stdout/stderr on nullifai_7z files\n"
            "Answers paper §IV-B: 'exact exception / point at which parsing fails'\n"
            "Tool: picklescan v0.0.22  |  Corpus seed: 42\n"
            + "=" * 60 + "\n"
        )
        # Save first 5 traces (representative; rest identical in structure)
        TRACE_PATH.write_text(header + "".join(traces[:5]))
        print(f"[run_scanners] nullifai_7z trace → {TRACE_PATH}")
        # Print first trace inline so it's visible in the run log
        print(f"[run_scanners] First nullifai_7z trace (inline):{traces[0]}")

    # ── Summary ───────────────────────────────────────────────────────────────
    print()
    print(f"[run_scanners] ── Scan log complete ──────────────────────────────")
    print(f"[run_scanners]  Total log entries : {len(log)}")

    for scanner_name, _ in _SCANNERS:
        rows = [e for e in log if e["scanner"] == scanner_name]
        n_flagged = sum(1 for e in rows if e["result"] == _R_FLAGGED)
        n_clean   = sum(1 for e in rows if e["result"] == _R_CLEAN)
        n_error   = sum(1 for e in rows if e["result"] == _R_ERROR)
        print(
            f"[run_scanners]  {scanner_name:<14} "
            f"flagged={n_flagged:5d}  "
            f"clean={n_clean:5d}  "
            f"error={n_error:5d}"
        )

    print(f"[run_scanners]  Log path          : {SCAN_LOG_PATH}")
    print(f"[run_scanners] ─────────────────────────────────────────────────")



if __name__ == "__main__":
    main()
