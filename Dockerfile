# ── Base ──────────────────────────────────────────────────────────────────────
# Python 3.11 slim — minimal Linux + Python, no dev tools or extras.
FROM python:3.11-slim

# ── System dependencies ────────────────────────────────────────────────────────
# Nmap is required for `mangekyo scan` and `mangekyo explain`.
# --no-install-recommends keeps the image lean.
# Cleaning up apt lists after install reduces image size.
RUN apt-get update \
    && apt-get install -y --no-install-recommends nmap \
    && rm -rf /var/lib/apt/lists/*

# ── Working directory ──────────────────────────────────────────────────────────
# All project files live at /app inside the container.
WORKDIR /app

# ── Copy project files ─────────────────────────────────────────────────────────
# Copy pyproject.toml first so Docker can cache the pip install layer.
# If only source code changes, Docker reuses the cached dependency layer
# and only rebuilds from the COPY src/ line onward — faster builds.
COPY pyproject.toml .
COPY src/ src/

# ── Install dependencies ───────────────────────────────────────────────────────
# --no-cache-dir keeps the image smaller by not storing pip's download cache.
RUN pip install --no-cache-dir -e .

# ── Bake in the model ─────────────────────────────────────────────────────────
# model.pkl is copied after pip install so changes to the model don't
# invalidate the dependency cache layer.
COPY model.pkl .

# ── Configuration ──────────────────────────────────────────────────────────────
# Tell Mangekyo where to find its data directory (model.pkl, caches, config).
ENV MANGEKYO_HOME=/app

# NVD_API_KEY must be passed at runtime — never bake secrets into an image.
# Pass it with: docker run -e NVD_API_KEY=your_key_here ...
ENV NVD_API_KEY=""

# ── Entrypoint ─────────────────────────────────────────────────────────────────
# Sets `mangekyo` as the default command so users run:
#   docker run ... ghcr.io/marckevf/mangekyo-cli score target.xml
# instead of:
#   docker run ... ghcr.io/marckevf/mangekyo-cli mangekyo score target.xml
ENTRYPOINT ["mangekyo"]

# Default to --help if no command is provided.
CMD ["--help"]
