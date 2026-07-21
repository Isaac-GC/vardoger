// vardoger: fake Android Context graph.
//
// One DeviceIdentity is the single source of truth for every fact a packer can
// query (package name, APK path, dirs, Build.*). AndroidEnv registers the
// host-impl methods + static fields + objects so a packer's attachBaseContext /
// JNI_OnLoad gets believable, internally-consistent answers. and
// the DeviceIdentity consistency checklist in §7.
#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "vardoger/jni/java_runtime.hpp"

namespace vardoger {

struct DeviceIdentity {
  // Use the sample's REAL package name + signing cert when you have them -
  // packers verify these. These are plausible defaults.
  std::string package_name = "com.victim.app";
  std::string apk_path = "/data/app/~~aB1==/com.victim.app-Xy2==/base.apk";
  std::string data_dir = "/data/user/0/com.victim.app/files";
  std::string native_lib_dir =
      "/data/app/~~aB1==/com.victim.app-Xy2==/lib/arm64";
  // A real, un-rooted physical device fingerprint (must match system props).
  std::string model = "Pixel 6";
  std::string manufacturer = "Google";
  std::string fingerprint =
      "google/raven/raven:12/SQ3A.220705.004/8836240:user/release-keys";
  int sdk_int = 31;
  // The signing certificate DER returned by signatures[0].toByteArray().
  // Empty => AndroidEnv fills a 256-byte placeholder. Set to the sample's real
  // META-INF/*.RSA cert when a packer hashes it.
  std::vector<uint8_t> signing_cert;
};

class AndroidEnv {
 public:
  AndroidEnv(JavaRuntime& jrt, DeviceIdentity id = {});

  // The Context/Application object handle to pass into native entry points.
  uint64_t application() const { return application_; }
  const DeviceIdentity& identity() const { return id_; }

 private:
  JavaRuntime& jrt_;
  DeviceIdentity id_;
  uint64_t application_ = 0;
};

// --- Full Android context object graph a packer's JNI_OnLoad /
// attachBaseContext walks --- AndroidEnv provides the device-identity base
// (Build.*, signature chain, Context getters). build_context_graph layers the
// RICHER reflected graph on top: ActivityThread -> AppBindData ->
// ApplicationInfo, PackageManager signatures/SigningInfo,
// ServiceManager/Binder, Context -> LoadedApk -> ClassLoader -> DexPathList,
// plus the java.util collections surface loaders walk. Call AFTER constructing
// AndroidEnv (its registrations override the device-base defaults for shared
// method names). Returns the object handles the driver hands to native entry
// points.
struct ContextGraphOptions {
  // The ClassLoader / Application proxy classes. Packers may `instanceof`-check
  // these, so classic Jiagu wants its own QHClassLoader / StubApp; the SDK path
  // keeps the framework defaults.
  std::string class_loader_class = "dalvik/system/PathClassLoader";
  std::string app_class = "android/app/Application";
  // Classic (VMOS-variant) extra probes:
  // getSoPath*/checkPermission/ContentResolver/storage dirs/
  // Locale/Collections.enumeration/Arrays.asList/etc. Off for SDK (keeps its
  // proven minimal graph).
  bool extra_probes = false;
};

struct ContextGraph {
  uint64_t context =
      0;  // android/content/Context (carries mPackageInfo/mOuterContext)
  uint64_t application = 0;  // the Application/StubApp handle (also
                             // ActivityThread.mInitialApplication)
  uint64_t activity_thread = 0;
  uint64_t class_loader = 0;
  uint64_t package_info = 0;
  uint64_t app_info = 0;
};

ContextGraph build_context_graph(JavaRuntime& jrt, const DeviceIdentity& id,
                                 const ContextGraphOptions& opt = {});

}  // namespace vardoger
