# Installation

## From PyPI (recommended)

```bash
pip install vardoger-vm
```

The wheel bundles Unicorn, Capstone, and zlib so no system libraries are needed.

---

## From source

### Prerequisites

CMake 3.22+, a C++20 compiler (GCC 11+ or Clang), pkg-config, and the development packages
for Unicorn (2.0+), Capstone (4.0+) and zlib.

=== "macOS"
    ```bash
    brew install cmake ninja pkg-config unicorn capstone zlib
    ```

=== "Ubuntu 24.04+ / Debian 12+"
    ```bash
    apt-get install build-essential cmake ninja-build pkg-config \
        libunicorn-dev libcapstone-dev zlib1g-dev
    ```

=== "Ubuntu 22.04"
    22.04 ships no `libunicorn-dev`. Build Unicorn and Capstone from source into
    `/usr/local` with the helper script, then point pkg-config at them:

    ```bash
    apt-get install build-essential cmake ninja-build pkg-config curl \
        libcapstone-dev zlib1g-dev
    sudo bash scripts/install_native_deps.sh
    export PKG_CONFIG_PATH=/usr/local/lib/pkgconfig LD_LIBRARY_PATH=/usr/local/lib
    ```

### Build

```bash
git clone https://github.com/Isaac-GC/vardoger
cd vardoger
cmake -B build -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build
```

This produces `build/libvardoger_capi.so` (Linux) or `build/libvardoger_capi.dylib` (macOS).

The Python package finds the library automatically when run from the repo root; you can
also point `$VARDOGER_CAPI` at it explicitly.

### Install the Python package in editable mode

```bash
pip install scikit-build-core
pip install -e .
```

---

## Library search order

When `import vardoger` is executed, `_native.py` looks for the shared library in this order:

1. `$VARDOGER_CAPI` environment variable (absolute path)
2. Next to `__init__.py` (installed wheel location)
3. `build/`, `build/linux/`, `build/mac/`, `build/pylib/` (repo checkout)

If none is found, a `FileNotFoundError` is raised with a hint.

---

## Verifying the install

```python
from vardoger import VM
vm = VM(package="com.example.app")
print("ok, version", vm)
```
