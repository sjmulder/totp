totp
====
From-scratch, dependency-free implementation of TOTP, including SHA1 -
for education.

Sources:
 - `totp.{c,h}` - the algorithms.
 - `std.{c,.h}` - some libc functions for freestanding targets (WASM,
   GBA).
 - `main.c` - a simple CLI.
 - `test.c` - unit tests.
 - `index.html` - a frondend for the WASM build.

Targets:
 - `totp` - the CLI.
 - `totp{32,64}.exe` - the CLI, for Windows.
 - `totp.wasm` - a WebAssembly build, used by `index.html`.

Building
--------
    make        # build CLI using default C compiler
    make cross  # build Windows and WASM targets

For Windows and WASM, default compilers and flags are specified in
the Makefile but can be overridden with make flags or `config.mk`,
which is automatically included if it exists.

Author
------
Sijmen Mulder (ik@sjmulder.nl). See LICENSE.md.
