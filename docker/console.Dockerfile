# The console image.
#
# Installs the [console] extra, which adds Jinja2, argon2-cffi and the form
# parser on top of the gateway's dependencies. Still no provider SDKs: those
# live in [dev] because they are differential-harness oracles, and CI asserts
# they are absent here too.
#
# SQLite needs nothing installed -- stdlib sqlite3 is enough, where the Go
# build needed a driver dependency for it.
FROM python:3.12-slim AS build

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /src
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

COPY pyproject.toml README.md LICENSE ./
COPY src ./src
RUN pip install --no-cache-dir ".[console]"


FROM python:3.12-slim

RUN useradd --system --create-home --uid 10001 hookguard

COPY --from=build /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    CONSOLE_DATA_DIR=/data

# The volume mount point. Owned by the runtime user, or the first write to the
# SQLite file fails on a fresh volume.
RUN mkdir -p /data && chown hookguard:hookguard /data
VOLUME ["/data"]

USER hookguard
EXPOSE 7000
ENTRYPOINT ["python", "-m", "hookguard_console"]
