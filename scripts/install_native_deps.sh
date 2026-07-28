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

# Force lib/ (not lib64/) so the install path is deterministic and matches the
# PKG_CONFIG_PATH/LD_LIBRARY_PATH set in pyproject's [tool.cibuildwheel.linux].
COMMON="-DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=/usr/local -DCMAKE_INSTALL_LIBDIR=lib -DBUILD_SHARED_LIBS=ON"

curl -sSL "https://github.com/capstone-engine/capstone/archive/refs/tags/${CAPSTONE_VERSION}.tar.gz" | tar xz
cmake -S "capstone-${CAPSTONE_VERSION}" -B cap $COMMON -DCAPSTONE_BUILD_TESTS=OFF
cmake --build cap --parallel
cmake --install cap

curl -sSL "https://github.com/unicorn-engine/unicorn/archive/refs/tags/${UNICORN_VERSION}.tar.gz" | tar xz
cmake -S "unicorn-${UNICORN_VERSION}" -B uni $COMMON -DUNICORN_ARCH="aarch64;arm"
cmake --build uni --parallel
cmake --install uni

ldconfig || true

# Fail loudly here (not later in an opaque CMake error) if the .pc files the
# wheel build's pkg_check_modules needs didn't get installed.
for pc in capstone unicorn; do
  test -f "/usr/local/lib/pkgconfig/${pc}.pc" ||
    { echo "ERROR: /usr/local/lib/pkgconfig/${pc}.pc missing after install" >&2; exit 1; }
done
