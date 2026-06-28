#!/bin/bash
# Version: 2026-04-02 v1.00
# Changes: Downloads official static musl fd binary (Rust) once on control machine for temporary fleet deployment. Latest version confirmed via releases.
set -e

FD_VERSION="10.4.2"
FD_ARCH="x86_64-unknown-linux-musl"
TARBALL="fd-v${FD_VERSION}-${FD_ARCH}.tar.gz"
URL="https://github.com/sharkdp/fd/releases/download/v${FD_VERSION}/${TARBALL}"

echo "Downloading fd v${FD_VERSION} static binary..."
curl -L --progress-bar -o "${TARBALL}" "${URL}"

tar -xzf "${TARBALL}"
mv "fd-v${FD_VERSION}-${FD_ARCH}/fd" ./fd
chmod +x ./fd
rm -rf "fd-v${FD_VERSION}-${FD_ARCH}" "${TARBALL}"

echo "✅ fd binary ready ($(ls -lh ./fd)) - now run fleet-find.sh with your hosts.txt"
