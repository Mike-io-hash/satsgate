FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    SATSGATE_PROXY_CONFIG=/etc/satsgate/proxy.yaml

WORKDIR /build
COPY proxy/pyproject.toml proxy/README.md /build/
COPY proxy/src /build/src
COPY proxy/snippets /usr/share/satsgate/snippets
COPY proxy/satsgate-proxy.example.yaml /usr/share/satsgate/satsgate-proxy.example.yaml
RUN pip install --no-cache-dir /build \
    && useradd --system --uid 65532 --no-create-home --shell /usr/sbin/nologin satsgate

USER 65532
EXPOSE 8080
CMD ["satsgate-proxy"]
