# The gateway image.
#
# Two stages: build a virtualenv with the [gateway] extra only, then copy it
# onto a clean runtime. The split matters for more than size -- the runtime
# carries no compiler and no build tooling, and the extra is what keeps the
# provider SDKs out of it. CI asserts that with the no-provider-sdk job.
#
# The Go build shipped a ~15MB static binary on distroless. This is larger,
# and honestly so: the README says so rather than pretending otherwise.
FROM python:3.12-slim AS build

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /src
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Dependency layer first, so editing source does not reinstall the world.
COPY pyproject.toml README.md LICENSE ./
COPY src ./src
RUN pip install --no-cache-dir ".[gateway]"


FROM python:3.12-slim

# A non-root user, matching the distroless nonroot the Go image used. The
# gateway is the only internet-facing surface in the system.
RUN useradd --system --create-home --uid 10001 hookguard

COPY --from=build /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

# Both routing tables ship; CONFIG_PATH selects one at runtime (default
# /config.json). Neither contains a secret -- only the NAME of the env var
# holding one.
COPY config.json /config.json
COPY config.fly.json /config.fly.json

USER hookguard
EXPOSE 9000
ENTRYPOINT ["python", "-m", "hookguard_gateway"]
