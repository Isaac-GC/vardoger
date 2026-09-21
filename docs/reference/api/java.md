# Java Surface

vardoger exposes a minimal but coherent JNI / Dalvik surface to the guest. These methods
let you create Java objects, strings, and arrays, read and write fields, and register
Python implementations for any Java method the native code calls.

---

## Objects & strings

### `new_string(s) → int`

Create a guest Java `String`; returns its handle (a stable integer for the lifetime of the VM).

### `new_object(cls) → int`

Create an uninitialized guest Java object of the given class descriptor.
`cls` may be a slash-form descriptor (`"Ljava/lang/Object;"`) or a dotted name.

```python
at = vm.new_object("Landroid/app/ActivityThread;")
```

### `find_class(name) → int`

Look up a class by its slash-form name. Returns a class handle (0 if not found).

---

## Arrays

### `new_byte_array(data) → int`

Create a guest `byte[]` from `data`; returns its handle.

### `new_object_array(elems) → int`

Create a guest `Object[]` from a list of object handles.

### `array_length(arr) → int`

Return the length of a guest array.

### `array_read(arr) → bytes`

Read the contents of a guest `byte[]`.

### `array_write(arr, data, off=0)`

Write bytes into a guest `byte[]` at `off` (grows if needed).

### `object_array_element(arr, i) → int`

Return the handle of element `i` in a guest `Object[]`.

---

## Fields

### `set_field(obj, name, value, *, is_object=True)`

Set a field on `obj`.

- `is_object=True` — `value` is an object handle.
- `is_object=False` — `value` is a raw integer (int/long/boolean).

### `get_field(obj, name) → (value, kind)`

Get a field. Returns `(int_value, kind)` where `kind` is `"void"`, `"int"`, or `"object"`.

---

## Method registration

```python
def get_package_name(self_h, args):
    return vm.new_string("com.example.app")

vm.register_method(
    "android/content/Context#getPackageName",
    get_package_name,
    returns_object=True,
)
```

### `register_method(name, fn, returns_object=True)`

Implement a Java method entirely in Python. `name` is `"owner#method"` in slash form
(e.g. `"java/lang/Class#forName"`).

`fn(self_handle: int, args: list[int]) -> int`:

- `self_handle` — the object the method was called on (0 for static calls).
- `args` — list of int64 arguments (object handles for reference types, raw values for primitives).
- return — object handle (`returns_object=True`) or raw integer.

Marshal strings with `vm.string_of(handle)` / `vm.new_string(s)`.

!!! note "Owner matching"
    The dispatcher matches on the owner class reported by the **guest object's class record**.
    Objects minted with `new_object` use the descriptor form (`"Ljava/lang/Object;"`); register
    both slash and descriptor variants if you are unsure which one the guest uses:
    ```python
    vm.register_method("java/lang/Class#forName", fn, True)
    vm.register_method("Ljava/lang/Class;#forName", fn, True)
    ```

---

## String utilities

### `string_of(handle, cap=65536) → str | None`

Read the value of a guest Java `String` handle. Returns `None` if the handle is invalid.
