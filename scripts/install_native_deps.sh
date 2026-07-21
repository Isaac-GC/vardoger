#!/usr/bin/env bash
# Build the native libraries vardoger links against (Unicorn, Capstone, zlib) inside the cibuildwheel
# manylinux container and install their pkg-config files so CMake's pkg_check_modules finds them.
# auditwheel later folds the resulting .so files into the wheel, so it ships self-contained.
set -euo pipefail

CAPSTONE_VERSION=5.0.1
UNICORN_VERSION=2.1.1

# zlib ships with most base images; install the dev package whichever manager is present.
(yum install -y zlib-devel || dnf install -y zlib-devel ||
 (apt-get update && apt-get install -y zlib1g-dev)) || true

work=$(mktemp -d)
cd "$work"

curl -sSL "https://github.com/capstone-engine/capstone/archive/refs/tags/${CAPSTONE_VERSION}.tar.gz" | tar xz
cmake -S "capstone-${CAPSTONE_VERSION}" -B cap -DCMAKE_BUILD_TYPE=Release -DCAPSTONE_BUILD_TESTS=OFF
cmake --build cap --parallel
cmake --install cap

curl -sSL "https://github.com/unicorn-engine/unicorn/archive/refs/tags/${UNICORN_VERSION}.tar.gz" | tar xz
cmake -S "unicorn-${UNICORN_VERSION}" -B uni -DCMAKE_BUILD_TYPE=Release -DUNICORN_ARCH="aarch64;arm"
cmake --build uni --parallel
cmake --install uni

ldconfig || true
