# The sample protected application.
#
# It verifies one Gateway signature and nothing else -- that is the whole
# demonstration. A real upstream replaces this and reimplements that single
# check in whatever language it is written in.
FROM python:3.12-slim AS build

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /src
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

COPY pyproject.toml README.md LICENSE ./
COPY src ./src
RUN pip install --no-cache-dir ".[gateway]"


FROM python:3.12-slim

RUN useradd --system --create-home --uid 10001 hookguard

COPY --from=build /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

USER hookguard
EXPOSE 8080
ENTRYPOINT ["python", "-m", "hookguard_gateway", "--upstream"]
