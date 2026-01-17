---

title: "Hideout-Maze Crackme Write-Up"
date: "2026-01-17T18:50:40+01:00"
lastmod: "2026-01-17T18:50:40+01:00"
author: ["Schnee"]

summary: "Multi-stage runtime unpacking crackme"

description: ""

weight: 0
slug: ""
draft: false
comments: true

showToc: false
TocOpen: false
hidemeta: false
disableShare: true
showbreadcrumbs: true

cover:
image: ""
caption: ""
alt: ""
relative: false
---------------

## Infos

* **Crackme Author:** dmarth
* **Crackme Link:** [https://ctf.cyberleague.at/challenges#Hideout%20Maze--979319403](https://ctf.cyberleague.at/challenges#Hideout%20Maze--979319403)
* **Platform:** ELF x64
* **Tools Used:** IDA, pwndbg

---

## Description

> After entering the secret hideout, you realize this was only the beginning.
>
> **Note:** The flag is in the format `acsc{...}`

---

## High-Level Overview

This crackme implements a **multi-stage runtime unpacker**. Each character of the input decrypts one 0x1000-byte code page using a simple `(~byte) ^ key` transformation. After decryption, execution jumps directly into the freshly unpacked code. The return value of the **final stage** determines whether the flag is correct.

Instead of fully emulating the execution flow in a debugger, the decryption logic can be reproduced offline, allowing the correct input bytes (the flag) to be recovered directly.

---

## Initial Reconnaissance

Running `strings` on the binary produces mostly meaningless output:

```
ATSH
[A\A]]
[A\]
AWAVUSH
[]A^A_
z0}ufH
HcD$
```

This suggests heavy obfuscation or runtime decryption, so the next step is static analysis in IDA.

---

## Static Analysis | IDA

Browsing through the binary reveals a large number of functions. However, referencing the few meaningful strings (those containing `flag`) leads to the main validation routine:

```c
v10 = **(char **)(input + 8);
sub_426CB0(0, 0, 0, 0);
v30 = *(_QWORD *)(input + 8);
j_ifunc_41E420(v30);
if ( *(_BYTE *)(v30 + 48) == 125 )
  goto LABEL_7;
...
v8 = stubFunction(*(_QWORD *)(input + 8));
free(stubFunction);
if ( v8 )
{
LABEL_7:
  sub_4109B0("Nope :(");
}
else
{
  sub_4109B0("Correct!");
}
```

1. A function pointer (`stubFunction`) is created dynamically
2. The input character is used as part of an XOR-based transformation
3. Execution jumps into the dynamically decrypted memory
4. The return value of the final function decides success or failure

Since `stubFunction` is generated at runtime, static analysis alone is insufficient.

---

## Dynamic Analysis | pwndbg

When running the binary under `gdb/pwndbg`, execution never finishes and gets stuck in an infinite loop. Using `strace` reveals that the binary calls `ptrace(PTRACE_TRACEME)`. When this call fails (as it does under a debugger), the program intentionally loops forever.

To bypass this anti-debugging mechanism, the return value check was patched so the result of `ptrace` is ignored:

```asm
mov     [rsp+0C8h+var_B4], 75BCD15h
call    sub_426CB0
test    rax, rax
nop
nop
```

With this patch in place, the binary executes normally under the debugger.

---

## The Decryption Stub

After bypassing the anti-debugging check, execution reaches the dynamically generated function (`stubFunction`). Disassembling it reveals the following logic:

```asm
movzx   r9, byte ptr [rdi]
inc     rdi
push    rdi
lea     rdi, sub_1000
mov     esi, (offset loc_2F004+2)
mov     edx, 7
mov     eax, 0Ah
syscall
xor     rcx, rcx
cmp     rcx, 2F006h
jge     short loc_40
movzx   r8, byte ptr [rdi+rcx]
not     r8b
xor     r8, r9
mov     [rdi+rcx], r8b
inc     rcx
jmp     short loc_23
mov     edx, 5
mov     eax, 0Ah
syscall
mov     eax, 1
mov     rbx, rdi
pop     rdi
jmp     rbx
```

Each stage works as follows:

* Read one input byte
* Use it as an XOR key
* Decrypt the next 0x1000-byte page using `(~byte) ^ key`
* Mark the page executable using `mprotect`
* Jump to the newly decrypted code

This pattern repeats for dozens of stages, one per input character.

---

## Offline Decryption Strategy

Since each stage applies the same transformation, the entire chain can be unpacked offline. One known plaintext byte is sufficient to recover the key. Conveniently, each decrypted stage ends with a `NOP (0x90)` instruction at a fixed offset.

Reversing the transformation:

```
byte = (~byte) ^ key  =>  key = (~cipher) ^ 0x90
```

This allows recovery of the input character for each stage.

### Unpacking Script

```python
PAGE   = 0x1000
SIZE   = 0x2f006
OFFSET = 0x60
NOP    = 0x90

with open("dump.bin", "rb") as f:
    data = bytearray(f.read())

base  = 0x0000
stage = 0
size  = SIZE
flag  = ""

while base + PAGE + OFFSET < len(data):
    enc_base = base + PAGE

    cipher = data[enc_base + OFFSET]
    key = ((~cipher) & 0xff) ^ NOP

    printable = chr(key) if 32 <= key <= 126 else "."
    print(f"[stage {stage:02d}] key = 0x{key:02x} ({printable})")
    flag += chr(key)

    for i in range(size):
        data[enc_base + i] = ((~data[enc_base + i]) & 0xff) ^ key

    if data[enc_base + OFFSET] != NOP:
        break

    base += PAGE
    size -= PAGE
    stage += 1

print(flag)
```

Running this script recovers:

```
acsc{1m_n0t_3v3n_m4d_th4ts_4M4Z31ng_jsOyD3Amczfo
```

---

## The Final Stage

The final decrypted page differs from the others: instead of decrypting another stage, it must **return 0** to signal success. Therefore, the decrypted bytes must form valid code ending in a `ret` instruction with `eax = 0`.

Testing possible input bytes and disassembling the resulting code reveals:

```
[key 'l'] mov eax, 0; ret
```

This provides the missing character. Since the flag format requires a closing brace, the final flag becomes:

```
acsc{1m_n0t_3v3n_m4d_th4ts_4M4Z31ng_jsOyD3Amczfol}
```

---

## Conclusion

This crackme demonstrates a multi-stage self-decrypting design combined with basic anti-debugging techniques. 

Overall, a very enjoyable challenge.