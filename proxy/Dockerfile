# python:3.12-slim
FROM python:3.12-slim@sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    SATSGATE_PROXY_CONFIG=/etc/satsgate/proxy.yaml

LABEL org.opencontainers.image.title="satsgate-proxy" \
    org.opencontainers.image.licenses="Apache-2.0" \
    org.opencontainers.image.source="https://github.com/Mike-io-hash/satsgate" \
    org.opencontainers.image.description="Charge AI agents in Lightning and USDC on the same 402. 500 free unlocks per UTC month. Cobrale a agentes de IA en Lightning y USDC, en el mismo 402."

ARG SOURCE_DATE_EPOCH=0
ENV SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH}

WORKDIR /build
COPY proxy/pyproject.toml proxy/README.md proxy/LICENSE /build/
COPY proxy/src /build/src
COPY proxy/snippets /usr/share/satsgate/snippets
COPY proxy/satsgate-proxy.example.yaml /usr/share/satsgate/satsgate-proxy.example.yaml
RUN pip install --no-cache-dir /build \
    && useradd --system --uid 65532 --no-create-home --shell /usr/sbin/nologin satsgate

USER 65532
EXPOSE 8080
CMD ["satsgate-proxy"]
