# Anti-Tamper Evasion

These variables suppress or redirect behavior that packers use to detect the analysis
environment or abort execution.

---

## VARDOGER_EXIT_NOOP

**Type:** boolean  
**Default:** disabled

Make `exit()` a no-op. Instead of terminating emulation, the guest returns from the
`exit` call to the caller (`lr`). The exit code is logged with `[exit]`.

```bash
export VARDOGER_EXIT_NOOP=1
```

Use when a packer calls `exit(N)` as an anti-debug trip-wire.

---

## VARDOGER_ABORT_NOOP

**Type:** boolean  
**Default:** disabled

Make `abort()` and `std::terminate()` no-ops. Returns to the caller instead of
raising `SIGABRT`. Logged with `[abort]`.

```bash
export VARDOGER_ABORT_NOOP=1
```

---

## VARDOGER_SLEEP_NOOP

**Type:** boolean  
**Default:** disabled

Make `sleep()` / `usleep()` return immediately without actually suspending. Useful
when a packer inserts large `sleep(30)` calls before decryption to frustrate
automated analysis.

```bash
export VARDOGER_SLEEP_NOOP=1
```

---

## VARDOGER_KILL_ESRCH

**Type:** boolean  
**Default:** disabled

When the guest calls `kill(own_pid, sig)` (classic watchdog `kill -0` check), return
`ESRCH` ("no such process") instead of delivering the signal. Convinces the packer
that its watchdog process does not exist and it is safe to proceed.

```bash
export VARDOGER_KILL_ESRCH=1
```

---

## VARDOGER_NO_TAMPER_EVASION

**Type:** boolean (negated — setting this DISABLES evasion)  
**Default:** disabled (evasion ON by default)

By default vardoger applies evasion hooks on `getenv`, `dlopen`, and `dlsym` to
return clean responses that do not reveal the analysis environment. Set this to
allow raw, un-intercepted behavior (e.g. for diagnostic purposes).

```bash
export VARDOGER_NO_TAMPER_EVASION=1
```

---

## VARDOGER_PROC_HIDE

**Type:** boolean  
**Default:** disabled

Hide `/proc/self/*` artifacts. `access()` and `stat()` on paths under `/proc/self`
return `ENOENT`. Packers that check `/proc/self/maps` for frida-server or
`/proc/self/status` for `TracerPid` see nothing.

```bash
export VARDOGER_PROC_HIDE=1
```
