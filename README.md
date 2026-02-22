# unasm

a two-pass assembler for [unisa](https://github.com/unarchitecture/unisa). takes `.asm` files and spits out flat binaries.

## build

```
gcc -std=c99 -o asm asm.c
```

one file, no dependencies.

## usage

```
./asm input.asm output.bin
```

## syntax

```asm
; comments start with semicolons
label:
    LDI R0, 72       ; load immediate
    ST R0, 0xF000    ; store to UART
    JMP label         ; jump to label
    HLT
```

- labels end with `:`, can be used as addresses anywhere
- labels are case-insensitive
- instructions can be upper or lower case
- numbers can be decimal (`42`) or hex (`0x2A`)

## directives

| directive | what it does |
|-----------|-------------|
| `.org addr` | set output position (e.g. `.org 0xEFF0` for the IVT) |
| `.db vals` | emit raw bytes — numbers (`.db 0x48, 0x65`), strings (`.db "Hi"`), or both |
| `.dw val` | emit a 16-bit value, little-endian — works with labels (`.dw my_handler`) |

## how it works

pass 1 scans for labels and tracks addresses. pass 2 emits bytes. that's it.

the opcodes are hardcoded to match the unisa CPU. if you change the ISA, you change the assembler.

## toolchain

this is one piece of the stack:

- [unisa](https://github.com/unarchitecture/unisa) — the cpu
- [unasm](https://github.com/unarchitecture/unasm) — the assembler (this repo)
- [unc](https://github.com/unarchitecture/unc) — the compiler
- [unos](https://github.com/unarchitecture/unos) — a tiny OS

## license

unlicense — do whatever you want with it
