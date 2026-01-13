---
title: "Simple VM Crackme Write-up"
date: "2026-01-12T21:36:43+01:00"
lastmod: "2026-01-12T21:36:43+01:00"
author: ["Schnee"]

summary: "Reverse-engineering write-up of a custom virtual machine crackme, focusing on VM emulation."

description: ""

weight: 0 # 1 means pin the article

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
---

## Infos

- **Crackme Author:** xer0  
- **Crackme Link:** https://ctf.cyberleague.at/challenges#vm1-1134631594
- **Platform:** ELF x64  
- **Tools Used:** IDA, Python  

---

## Description

"Introduction to virtual machines. This challenge is a simple VM"

## Initial Reconnaissance

Running the binary without input:

```bash
./vm
Failed to open program file
```
The program expects a file named program.bin. With the file present, the program waits for user input and prints either:
- Success: Input matches the flag!
- Failure: Input does not match the flag.

Running strings on the binary reveals little of interest besides standard libc functions.
This suggests the validation logic is hidden behind the VM.

## Static Analysis | IDA
The main function performs the following steps:

- Initializes a VM state buffer
- Loads program.bin into VM memory
- Reads 20 bytes from stdin
- Executes the VM
- Checks a VM register to determine success

```C
read(0, v8, 0x14u);
run_vm(v6);
if ( v6[0] == 8 )
  puts("Success: Input matches the flag!");
else
  puts("Failure: Input does not match the flag.");
```

- Input length is exactly 20 bytes
- VM register v6[0] acts as a success flag

## VM State Layout

From init_vm() and run_vm() we can reconstruct the VM memory layout:
| Offset | Purpose |
|--------|---------|
| 0      | Comparison flag |
| 1–7    | Registers |
| 8–263  | VM memory |
| 264    | Program counter |
| 265    | Running flag |
| 266    | Debug flag |

## VM Instruction Set

From execute_instruction() we can extract the full opcode table:

| Opcode | Description |
|--------|-------------|
| 0x00   | MOV reg, reg |
| 0x01   | MOV reg, imm |
| 0x02   | MOV reg, mem |
| 0x03   | ADD reg, reg |
| 0x04   | CMP reg, mem |
| 0x05   | CMP reg, reg |
| 0xF0   | JMP_IF_EQ |
| 0xF1   | JMP_IF_NEQ |
| 0xFF   | HALT |

## VM Interpreter

I wrote a Python interpreter which:
- Implements the VM instruction set
- Forces all CMP instructions to succeed
- Ignores failure jumps
- Logs every comparison against input memory

```Python
code = open("program.bin", "rb").read()

R = [0] * 300
pc = 0
flag = {}

while pc < len(code):
    op = code[pc]
    pc += 1

    if op == 0x00:      # MOV R[a], R[b]
        a, b = code[pc:pc+2]
        pc += 2
        R[a] = R[b]

    elif op == 0x01:    # MOV R[a], imm
        a, imm = code[pc:pc+2]
        pc += 2
        R[a] = imm

    elif op == 0x02:    # MOV R[a], MEM[b]
        a, b = code[pc:pc+2]
        pc += 2
        R[a] = R[b + 8]

    elif op == 0x03:    # ADD
        a, b = code[pc:pc+2]
        pc += 2
        R[a] = (R[a] + R[b]) & 0xff

    elif op == 0x04:    # CMP R[a], MEM[b]
        a, b = code[pc:pc+2]
        pc += 2

        idx = (b + 8) - 0xEC
        if 0 <= idx < 32:
            flag[idx] = R[a]
            print(f"[+] {idx:02} -> {chr(R[a])}")

    elif op == 0xF1:    # JNE
        pc += 1         # ignore jump

    elif op == 0xFF:
        break

    else:
        break


print("\nFlag:")
print(bytes(flag[i] for i in sorted(flag)).decode())
```

## Final Flag
```
CLAM{f1rst_vm_2097ab}
```

Result:
```
Success: Input matches the flag!
```

## Conclusion
Overall a fun introduction to VMs. I like that the binary wasn't stripped for simplicity and that printf statements for each Instruction was present, which made this challenge simpler.
