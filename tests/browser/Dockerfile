# Headless Chromium for the browser tests (used when the host only has a sandboxed snap Chromium).
FROM debian:bookworm-slim
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      chromium fonts-dejavu-core ca-certificates && rm -rf /var/lib/apt/lists/*
ENTRYPOINT ["chromium", "--headless", "--no-sandbox", "--disable-gpu", "--disable-dev-shm-usage", \
            "--remote-debugging-address=127.0.0.1", "--user-data-dir=/tmp/profile"]
