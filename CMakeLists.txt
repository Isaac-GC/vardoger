cmake_minimum_required(VERSION 3.24)
project(vardoger LANGUAGES CXX VERSION 0.3.0)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(PkgConfig REQUIRED)
pkg_check_modules(UNICORN REQUIRED IMPORTED_TARGET unicorn)
pkg_check_modules(CAPSTONE REQUIRED IMPORTED_TARGET capstone)
pkg_check_modules(ZLIB REQUIRED IMPORTED_TARGET zlib)

# The engine, grouped by subsystem. See include/vardoger/ for the public headers.
add_library(vardoger_core
        # engine: CPU, memory, scheduling
        core/engine/engine.cpp
        core/engine/disassembler.cpp
        core/engine/tracer.cpp
        core/engine/memory.cpp
        core/engine/trampoline.cpp
        core/engine/scheduler.cpp
        core/engine/gdb_stub.cpp
        # elf: the loader
        core/elf/elf_loader.cpp
        # android: the guest OS surface (libc stubs, syscalls, vfs, context)
        core/android/stubs.cpp
        core/android/android_env.cpp
        core/android/system.cpp
        core/android/vfs.cpp
        core/android/syscalls.cpp
        # jni: the Java bridge and runtime
        core/jni/java_runtime.cpp
        core/jni/jni.cpp
        # dex: parser, mini-Dalvik, lifecycle
        core/dex/dex_file.cpp
        core/dex/dalvik.cpp
        core/dex/lifecycle.cpp
        # art: the class-resolution runtime and ART bring-up
        core/art/art_runtime.cpp
        core/art/art_bringup.cpp
        # extract: payload capture and debug hooks
        core/extract/extractor.cpp
        core/extract/debug_hooks.cpp
)
target_include_directories(vardoger_core PUBLIC include third_party)
target_link_libraries(vardoger_core PUBLIC PkgConfig::UNICORN PkgConfig::CAPSTONE PkgConfig::ZLIB)
set_property(TARGET vardoger_core PROPERTY POSITION_INDEPENDENT_CODE ON)

# vardoger_capi: the flat C ABI that the Python package drives through ctypes. It is a shared
# library so ctypes can dlopen it, and it pulls in the whole engine.
add_library(vardoger_capi SHARED core/py/vardoger_capi.cpp)
target_link_libraries(vardoger_capi PRIVATE vardoger_core PkgConfig::UNICORN PkgConfig::CAPSTONE PkgConfig::ZLIB)
set_target_properties(vardoger_capi PROPERTIES POSITION_INDEPENDENT_CODE ON)

# When scikit-build-core drives the build for a wheel, drop the shared library straight into the
# installed package so the ctypes loader finds it next to __init__.py.
if(DEFINED SKBUILD)
    install(TARGETS vardoger_capi LIBRARY DESTINATION vardoger RUNTIME DESTINATION vardoger)
endif()
