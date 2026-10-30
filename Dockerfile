# ──────────────────────────────────────────────────────────────────────────────
# Pickle Scanner–Loader Mismatch Evaluation Harness
# Dockerfile
#
# NETWORK ISOLATION: Build with --network none is NOT supported during `docker build`
# (pip needs the internet at build time).  Run the CONTAINER with --network none:
#   docker run --network none ...
# The loader observer (observe_load.py) also checks at runtime that no egress
# route is reachable and refuses to run if one is found.
# ──────────────────────────────────────────────────────────────────────────────

FROM python:3.11-slim

# ── System dependencies needed by py7zr ──────────────────────────────────────
RUN apt-get update && apt-get install -y --no-install-recommends \
        p7zip-full \
    && rm -rf /var/lib/apt/lists/*

# ── Working directory inside the container ───────────────────────────────────
WORKDIR /harness

# ── Install Python deps first (layer caching) ────────────────────────────────
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# ── PyTorch CPU-only (mechanism elimination testing: weights_only=True) ──────
# Installed separately because it requires a non-default index URL.
# CPU-only build (~450 MB) is sufficient; no GPU is needed for unpickling tests.
RUN pip install --no-cache-dir torch \
    --index-url https://download.pytorch.org/whl/cpu


# ── Copy project source ───────────────────────────────────────────────────────
COPY . .

# ── Non-root user (paper isolation: §IV-B) ────────────────────────────────────
# Running as UID 1000 limits blast radius if a payload escapes the Python layer.
# The harness writes only to /harness/corpus, /harness/results, and /tmp.
RUN groupadd -r harness && \
    useradd  -r -g harness -u 1000 --no-create-home harness && \
    chown -R harness:harness /harness

# ── Make entrypoint executable ────────────────────────────────────────────────
RUN chmod +x run_all.sh

# Switch to non-root for all runtime operations
USER harness

# ── Default: run the full pipeline ───────────────────────────────────────────
# Full recommended docker run command (see README §IV-B):
#
#   docker run --rm                     \
#       --network none                  \
#       --user 1000:1000                \
#       --read-only                     \
#       --tmpfs /tmp:size=256m,noexec   \
#       --tmpfs /harness/corpus:size=2g \
#       --tmpfs /harness/results:size=512m \
#       --ulimit nproc=256:256          \
#       --ulimit nofile=1024:1024       \
#       --memory 4g                     \
#       --cpus 4                        \
#       -v "$(pwd)/results:/harness/results" \
#       pickle-harness:latest
#
CMD ["bash", "run_all.sh"]
