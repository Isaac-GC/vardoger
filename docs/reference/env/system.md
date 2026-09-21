# System Environment

These variables control what the guest sees as its runtime environment: process name,
system properties, and Java lifecycle parameters.

---

## VARDOGER_PROGNAME

**Type:** string  
**Default:** package name (or `MINVM_PROGNAME` if set)

Override the guest process name returned by `__progname`, `getprogname()`, and
`/proc/self/cmdline`. Some RASP (LIApp, certain Jiagu variants) gate self-decryption
on `__progname` matching the expected package name and fail silently if it does not.

```bash
export VARDOGER_PROGNAME=com.example.app
```

Equivalent to `vm.set_progname("com.example.app")`. Must be set **before** `vm.load()`
since the name is resolved at relocation time.

---

## MINVM_PROGNAME

**Type:** string  
**Default:** none

Legacy alias for `VARDOGER_PROGNAME`. Used only if `VARDOGER_PROGNAME` is not set.

---

## VARDOGER_PROPS

**Type:** string (comma-separated `key=value` pairs)  
**Default:** none

Override system property responses inline without calling `vm.set_property()`:

```bash
export VARDOGER_PROPS="ro.debuggable=0,ro.build.fingerprint=google/redfin/redfin:11/RQ3A.210905.001/7511028:user/release-keys"
```

Values set here take priority over vardoger's default property table. Any key the
guest queries via `__system_property_get` is checked here first.

---

## VARDOGER_ENTRY_CLASS

**Type:** string (DEX descriptor)  
**Default:** auto-detected

Override the DEX entry class used for the Java lifecycle (the `Application` subclass
whose `attachBaseContext` / `onCreate` are driven by `vm.run_lifecycle()`).

```bash
export VARDOGER_ENTRY_CLASS=Lcom/example/PackerApp;
```

Use when auto-detection picks the wrong class or the stub is obfuscated.

---

## VARDOGER_NO_MMAINTHREAD

**Type:** boolean (negated)  
**Default:** disabled (main thread IS populated)

When set, the JNI layer does not populate the main `ActivityThread` object. Useful for
diagnosing issues related to the main-thread initialization path.

---

## VARDOGER_NO_FIELD_DEFAULTS

**Type:** boolean (negated)  
**Default:** disabled (field defaults ARE set)

When set, Java objects are allocated without populating any default field values
(e.g. string fields are left null). Diagnostic only.
