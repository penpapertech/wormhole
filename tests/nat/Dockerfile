FROM debian:trixie-slim
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      iproute2 iptables python3 procps conntrack openssl ca-certificates \
      chromium nodejs fonts-dejavu-core && rm -rf /var/lib/apt/lists/*
