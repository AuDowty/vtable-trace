# vtable-trace

Dump a C++ object's vtable in a running Windows process and (optionally) trace calls to each entry.

Pairs with [`minhook-cli`](https://github.com/AuDowty/minhook-cli) (same debug-API foundation) and [`pe-info`](https://github.com/AuDowty/pe-info) (resolve a module's exported `vtable for X` symbol or just a base + offset).

## Install

```
cargo install --git https://github.com/AuDowty/vtable-trace
```

Windows only.

## Use

Dump a vtable at a given address (the object's first qword is its vtable pointer):

```
vtable-trace dump --pid 1234 --obj 0x00000200_abcd1000
```

Output:

```
object  : 0x00000200abcd1000
vtable  : 0x00007ff7_4a0_b500
entries : 12

#  RVA           ABSOLUTE          MODULE      OFFSET
0  0x0001b520    0x7ff74a01b520    foo.dll     +0x1b520
1  0x0001b540    0x7ff74a01b540    foo.dll     +0x1b540
...
```

Trace every call into one entry of the vtable (uses INT3 breakpoint, see [minhook-cli](https://github.com/AuDowty/minhook-cli)):

```
vtable-trace trace --pid 1234 --obj 0x00000200_abcd1000 --slot 3
```

Or trace by absolute target address (skip vtable resolution):

```
vtable-trace trace --pid 1234 --addr 0x7ff74a01b540
```

## How it works

1. **Dump**: read 8 bytes at `obj` → that's the vtable pointer. Read N qwords at the vtable → those are the function pointers. Each is resolved to (module + RVA) by enumerating loaded modules and bracketing.
2. **Trace**: pick a slot, install an `INT3` at the function the slot points to, attach via `DebugActiveProcess`, log registers + return address on each hit, restore the byte + single-step + re-arm. Same mechanism as `minhook-cli`.

The dump phase is read-only (`OpenProcess` with just `PROCESS_VM_READ`); trace needs write + debug rights.

## License

MIT.
