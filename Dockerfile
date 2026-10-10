FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1

# policies/ is written for Rego v1, so the sidecar is pinned to the release this
# repo was verified against (opa test 69/69, pytest 45 passed) instead of tracking
# the release feed. Checksum is the one published on that release's assets.
# The `v` is part of the tag: OPA's release assets live under download/v<version>,
# and a bare version number 404s the build.
ARG OPA_VERSION=1.21.1
ARG OPA_SHA256=668506eb17a2eaa1fce6cc0d1f42ef85125d4ac5bda5fc74d1152d0c77145031
ADD https://github.com/open-policy-agent/opa/releases/download/v${OPA_VERSION}/opa_linux_amd64_static /usr/local/bin/opa
RUN echo "${OPA_SHA256}  /usr/local/bin/opa" | sha256sum --check --strict \
 && chmod 0755 /usr/local/bin/opa \
 && opa version | head -1

WORKDIR /app

COPY pyproject.toml README.md ./
COPY src ./src
RUN pip install .

COPY policies ./policies
COPY data ./data
COPY scripts ./scripts
COPY ops ./ops

# The gates this repo enforces locally, enforced against the artifact that ships:
# the replayability lint plus a bundle that must load its own tables and carry the
# revision it was stamped with. scripts/opa_serve.sh --bundle needs builds/ to
# already exist, so the build happens here rather than at container start.
ENV OPA_BIN=/usr/local/bin/opa
RUN sh scripts/policy_test.sh \
 && sh scripts/policy_build.sh

RUN useradd --create-home --uid 10001 app \
 && mkdir -p /app/var \
 && chown -R app:app /app
USER app

ENV ENGINE_HOST=0.0.0.0 \
    DATA_DIR=/app/var

EXPOSE 10000
ENTRYPOINT ["sh", "/app/ops/docker-entrypoint.sh"]
