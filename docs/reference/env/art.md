# ART / DEX Runtime

These variables enable the ART substrate — the layer that replicates Android Runtime
internals so packers that hook or scan ART classes work correctly.

---

## VARDOGER_ART

**Type:** boolean  
**Default:** disabled

Enable ART DEX-load boundary instrumentation. Wires hooks on:

- `openInMemoryDexFile` / `openDexFileNative`
- `defineClassNative`
- `getClassNameList`

Also makes `makeDexElements` / `makeInMemoryDexElements` / `makePathElements` work
against the substrate. Any DEX buffer crossing these boundaries fires the
`set_dex_observer` callback and lands in `scan_dex()`.

```bash
export VARDOGER_ART=1
```

This is the primary flag for class-load-decrypt packers (dpt-shell, FART variants,
Jiagu class-extract mode).

---

## VARDOGER_ART_RUNTIME

**Type:** boolean  
**Default:** disabled

Enable ART runtime substrate bringup (ART Runtime object initialization). Usually
implied by `VARDOGER_ART_CLASSLINKER`; set independently only when you need the
Runtime object populated without a full ClassLinker.

---

## VARDOGER_ART_CLASSLINKER

**Type:** boolean  
**Default:** disabled

Strategy A: bring up a real `ClassLinker` within the ART substrate. Populates ART
internal pointers (`runtime`, `thread`, `class_linker`, `heap`, `linear_alloc`,
`intern_table`) accessible via `vm.art_bringup()`. Required when a packer patches or
calls `ClassLinker::DefineClass` directly.

```bash
export VARDOGER_ART=1
export VARDOGER_ART_CLASSLINKER=1
```

Pairs with `vm.map_art(art_dir)` to supply the real libart.so.

---

## VARDOGER_ART_HOOKABLE

**Type:** boolean  
**Default:** disabled

Strategy A3: make the libart image write-flippable. After mapping, the text segment
is remapped R/W so FART-style packers that patch ART method entry points (e.g.
`ArtMethod::nterp_entry_point`) can write to it without faulting.

```bash
export VARDOGER_ART=1
export VARDOGER_ART_CLASSLINKER=1
export VARDOGER_ART_HOOKABLE=1
```
