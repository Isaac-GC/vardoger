// vardoger: generic, packer-agnostic debug/instrumentation hooks.
//
// A grab-bag of UC_HOOK_* instrumentation levers driven purely by VARDOGER_* env
// vars, no packer offsets baked into the hook bodies. Factored out of
// so every driver (jiagu, ijiami, sdk, ducex,
// virbox) can arm the same watches/traces with one call.
//
// The caller resolves the sample-specific addresses (load bias, RC4 KSA/PRGA
// PCs, …) and passes them in; install_debug_hooks reads the env, and for each
// set VARDOGER_* var arms the matching hook. Unset vars are a no-op. See
//
#pragma once

#include <cstdint>

#include "vardoger/engine/engine.hpp"

namespace vardoger {

// Sample-specific addresses the generic hooks need (the driver computes these;
// the hook bodies stay packer-agnostic). All are GUEST (biased) addresses; 0
// means "not resolved / feature unavailable".
struct DebugHookOptions {
  uint64_t load_bias =
      0;  // SO base, SO-relative offsets in the log output / default ranges
  uint64_t ksa_pc = 0;       // VARDOGER_KSA_DUMP=auto target (RC4 KSA prologue)
  uint64_t rc4_ksa_pc = 0;   // VARDOGER_RC4_FAST KSA intercept
  uint64_t rc4_prga_pc = 0;  // VARDOGER_RC4_FAST PRGA intercept
};

// Read the VARDOGER_* env vars and arm the corresponding generic hooks on `e`.
// Covers:
//   VARDOGER_XWATCH, VARDOGER_ADDRWATCH, VARDOGER_DEXWRITE, VARDOGER_BT, VARDOGER_TRACEPC,
//   VARDOGER_MEMREAD (+ VARDOGER_MEMREAD_TGT), VARDOGER_KSA_DUMP, VARDOGER_RC4_FAST (+
//   VARDOGER_RC4_LOG/_DUMP), VARDOGER_ITRACE (+ VARDOGER_ITRACE_BITPOS/_XWIDE).
// No-op for any var that is unset. Idempotent-per-process only in the sense
// that the hook state is file-scope; call once per run.
void install_debug_hooks(Engine& e, const DebugHookOptions& opt);

}  // namespace vardoger
