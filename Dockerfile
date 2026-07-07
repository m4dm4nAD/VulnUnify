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

COPY backend ./backend
COPY migrations ./migrations
COPY frontend ./frontend
COPY alembic.ini ./

EXPOSE 8000
CMD ["uvicorn", "backend.app.main:app", "--host", "0.0.0.0", "--port", "8000"]
