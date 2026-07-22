FROM python:3.12-slim

# PowerShell + Az module are needed only for the Defender for Cloud connector.
# Install lazily; comment out if you don't use PowerShell-based connectors.
#
# NOTE: The Microsoft Debian repo is signed with a SHA1 key, which apt rejects
# since 2026-02-01 ("repository is not signed"), breaking the build. Left
# disabled. Re-enable ONLY if you use the Defender connector, and expect to
# work around the signature policy (e.g. pin an older base image or add the
# key with a relaxed policy).
# RUN apt-get update \
#     && apt-get install -y --no-install-recommends curl gnupg ca-certificates \
#     && curl -sSL https://packages.microsoft.com/config/debian/12/packages-microsoft-prod.deb -o /tmp/ms.deb \
#     && dpkg -i /tmp/ms.deb && rm /tmp/ms.deb \
#     && apt-get update && apt-get install -y --no-install-recommends powershell \
#     && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY pyproject.toml ./
RUN pip install --no-cache-dir -e .

# ---- Clearwing (sourcehunt) — EXPERIMENTAL, enables real source-code scans ----
# Installed in the SAME env as the app (the Code Scan feature imports
# clearwing.sourcehunt.runner directly). Kept OUT of pyproject.toml so the app's
# dependency layer stays decoupled and cacheable. Its own trailing layer isolates
# the heavy (~1-2GB) native tree; the import smoke-check fails the build loudly if
# resolution/compile breaks. Disable with:  --build-arg WITH_CLEARWING=0
# git + libpcap0.8 stay in the image (repo clone at scan time / libpnet runtime);
# the compiler + Rust toolchain are added and purged inside this one layer.
ARG WITH_CLEARWING=1
RUN set -eux; \
    if [ "$WITH_CLEARWING" = "1" ]; then \
      apt-get update; \
      apt-get install -y --no-install-recommends git libpcap0.8; \
      apt-get install -y --no-install-recommends \
          build-essential pkg-config cargo libpcap-dev libssl-dev libffi-dev; \
      pip install --no-cache-dir "clearwing @ git+https://github.com/Lazarus-AI/clearwing"; \
      python -c "import clearwing.sourcehunt.runner; print('clearwing import OK')"; \
      apt-get purge -y --auto-remove \
          build-essential pkg-config cargo libpcap-dev libssl-dev libffi-dev; \
      rm -rf /var/lib/apt/lists/* /root/.cargo /root/.cache; \
    fi

# ---- Deepened sourcehunt runtime toolchain (kept in the image) ----
# clang/LLVM + bear: sanitizer-validated exploit development (ASan/UBSan compile
# of the target at scan time). gh: opens the draft PR when auto_pr is enabled.
# Only needed for the exploit/patch/PR options; disable with --build-arg
# WITH_HUNT_TOOLCHAIN=0 to keep the image slim for discovery-only scans.
ARG WITH_HUNT_TOOLCHAIN=1
ARG GH_VERSION=2.62.0
RUN set -eux; \
    if [ "$WITH_HUNT_TOOLCHAIN" = "1" ]; then \
      apt-get update; \
      apt-get install -y --no-install-recommends clang llvm bear curl ca-certificates; \
      arch="$(dpkg --print-architecture)"; \
      curl -fsSL "https://github.com/cli/cli/releases/download/v${GH_VERSION}/gh_${GH_VERSION}_linux_${arch}.tar.gz" \
        -o /tmp/gh.tgz; \
      tar -xzf /tmp/gh.tgz -C /tmp; \
      mv "/tmp/gh_${GH_VERSION}_linux_${arch}/bin/gh" /usr/local/bin/gh; \
      gh --version; clang --version | head -1; bear --version || true; \
      rm -rf /tmp/gh.tgz "/tmp/gh_${GH_VERSION}_linux_${arch}" /var/lib/apt/lists/*; \
    fi

COPY backend ./backend
COPY migrations ./migrations
COPY frontend ./frontend
COPY alembic.ini ./

EXPOSE 8000
CMD ["uvicorn", "backend.app.main:app", "--host", "0.0.0.0", "--port", "8000"]
