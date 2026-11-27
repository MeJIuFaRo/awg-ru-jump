FROM ubuntu:24.04@sha256:562111b88caa79c71391c0c4d3c2114a7d5c35915c20561fd893cb1e07929e6b
ARG WARP_VERSION=2026.8.2115.0
RUN set -eu; export DEBIAN_FRONTEND=noninteractive; \
    apt-get update; \
    apt-get install -y --no-install-recommends ca-certificates curl gnupg iproute2 nftables iptables; \
    curl --proto '=https' -fsSL https://pkg.cloudflareclient.com/pubkey.gpg -o /tmp/warp-repository.asc; \
    actual=$(gpg --batch --show-keys --with-colons /tmp/warp-repository.asc | awk -F: '$1=="pub"{primary=1} $1=="fpr" && primary{print $10; primary=0}'); \
    test "$actual" = C068A2B5771775193CBE1F2F6E2DD2174FA1C3BA; \
    gpg --batch --dearmor -o /usr/share/keyrings/cloudflare-warp.gpg /tmp/warp-repository.asc; \
    echo 'deb [arch=amd64 signed-by=/usr/share/keyrings/cloudflare-warp.gpg] https://pkg.cloudflareclient.com/ noble main' > /etc/apt/sources.list.d/cloudflare-warp.list; \
    apt-get update; \
    apt-get install -y --no-install-recommends "cloudflare-warp=$WARP_VERSION"; \
    rm -f /tmp/warp-repository.asc; rm -rf /var/lib/apt/lists/*; \
    install -d -m 0755 /run/cloudflare-warp /var/log/cloudflare-warp; \
    install -d -m 0700 /var/lib/cloudflare-warp
ENTRYPOINT ["/bin/warp-svc"]
