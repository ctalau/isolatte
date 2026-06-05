# gondolin-qemu-tcg-poc
#
# Runs the Gondolin QEMU-TCG proof-of-concept inside a container.
# No /dev/kvm required: QEMU runs in software-emulation (TCG) mode.
#
# Build:
#   docker build -t gondolin-tcg-poc .
#
# Run:
#   docker run --rm gondolin-tcg-poc
#
# The ~98 MB Gondolin guest image is baked in during build (no network needed at runtime).
# To persist the image cache across rebuilds, mount a volume:
#   docker run --rm -v gondolin-cache:/root/.cache/gondolin gondolin-tcg-poc

FROM node:20-bookworm-slim

# QEMU for TCG software emulation; no KVM device needed
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        qemu-system-x86 \
        qemu-utils \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Inject the egress-proxy CA chain so npm and Node.js fetch can reach the
# internet through the TLS-intercepting proxy.  Only needed at build time.
COPY egress-ca-bundle.pem /tmp/egress-ca-bundle.pem

# Install Node dependencies (reproducible install from lockfile)
COPY package.json package-lock.json ./
RUN NODE_EXTRA_CA_CERTS=/tmp/egress-ca-bundle.pem npm ci --omit=dev

# Pre-download the Gondolin guest image (~98 MB) into the default cache dir
# so the container can run without outbound network access at runtime.
COPY predownload.mjs ./
RUN NODE_EXTRA_CA_CERTS=/tmp/egress-ca-bundle.pem node predownload.mjs

COPY poc.mjs ./

CMD ["node", "poc.mjs"]
