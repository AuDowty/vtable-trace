# vtable-trace

Dump a C++ object's vtable in a running Windows process. Optionally trace calls to individual entries via INT3 breakpoints.

Pairs with [minhook-cli](https://github.com/AuDowty/minhook-cli) and [pe-info](https://github.com/AuDowty/pe-info).

## Install

```
cargo install --git https://github.com/AuDowty/vtable-trace
```

Windows only.

## Use

Dump a vtable:

```
vtable-trace dump --pid 1234 --obj 0x00000200_abcd1000
```

Trace calls to a specific vtable slot:

```
vtable-trace trace --pid 1234 --obj 0x00000200_abcd1000 --slot 3
```

Or trace by absolute address:

```
vtable-trace trace --pid 1234 --addr 0x7ff74a01b540
```

Dump is read-only (`PROCESS_VM_READ`). Trace needs write + debug rights.

## License

MIT
