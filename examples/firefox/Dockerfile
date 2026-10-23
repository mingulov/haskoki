# Match the p11-kit RPC version in the pinned Haskoki image. Debian's 0.25.5
# client sends incompatible NULL mechanism arrays to that 0.26.2 server.
FROM debian:trixie-slim AS client-build
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc libc6-dev meson ninja-build pkg-config libffi-dev gettext python3 xz-utils \
    && rm -rf /var/lib/apt/lists/*
ADD --checksum=sha256:09fd9f44da4813a3141e73d5e7cf7008e5660d0405f13d56c15e1da9dcecf828 \
    https://github.com/p11-glue/p11-kit/releases/download/0.26.2/p11-kit-0.26.2.tar.xz /tmp/p11-kit.tar.xz
RUN umask 022 && tar -xf /tmp/p11-kit.tar.xz -C /tmp \
    && meson setup /tmp/p11-build /tmp/p11-kit-0.26.2 \
       -Dtrust_module=disabled -Dsystemd=disabled -Dbash_completion=disabled \
       -Dzsh_completion=disabled -Dgtk_doc=false -Dman=false -Dnls=false -Dtest=false \
    && meson compile -C /tmp/p11-build -j 2 p11-kit-client \
    && mkdir -p /opt/haskoki-p11-kit \
    && cp /tmp/p11-build/p11-kit/p11-kit-client.so /opt/haskoki-p11-kit/ \
    && cp /tmp/p11-kit-0.26.2/COPYING /opt/haskoki-p11-kit/ \
    && printf '%s\n' 'p11-kit 0.26.2' \
       'https://github.com/p11-glue/p11-kit/releases/download/0.26.2/p11-kit-0.26.2.tar.xz' \
       'source-sha256 09fd9f44da4813a3141e73d5e7cf7008e5660d0405f13d56c15e1da9dcecf828' \
       > /opt/haskoki-p11-kit/source.txt

FROM debian:trixie-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
    firefox-esr libnss3-tools p11-kit opensc opensc-pkcs11 nginx libffi8 \
    xvfb novnc websockify x11vnc python3 openssl ca-certificates fonts-dejavu-core \
    && rm -rf /var/lib/apt/lists/*
COPY --from=client-build /opt/haskoki-p11-kit/ /opt/haskoki-p11-kit/
RUN ldd /opt/haskoki-p11-kit/p11-kit-client.so > /opt/haskoki-p11-kit/ldd.txt \
    && ! grep -Eq 'not found|libp11-kit' /opt/haskoki-p11-kit/ldd.txt \
    && sha256sum /opt/haskoki-p11-kit/p11-kit-client.so > /opt/haskoki-p11-kit/client.sha256
ENV HOME=/out/home DISPLAY=:99 P11_KIT_SERVER_ADDRESS=unix:path=/out/token.sock
WORKDIR /out
CMD ["python3", "/example/browser.py", "start"]
