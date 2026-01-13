---
title: "Hideout Crackme Write-Up"
date: "2026-01-13T18:50:40+01:00"
lastmod: "2026-01-13T18:50:40+01:00"
author: ["Schnee"]

summary: "An intro into runtime unpacking"

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
- **Crackme Author: dmarth**  
- **Crackme Link: https://ctf.cyberleague.at/challenges#Hideout-526176016**
- **Platform: ELF x64**  
- **Tools Used: IDA, pwndbg**  
---

## Description
"It seems the real functionality of this access module is hidden. Can you uncover the secret flag anyway?"

---

## Initial Reconnaissance

Running the strings showed a lot of noise:
```
strings hideout
u=E1
ATSH
[A\A]]
[A\]
AVAUATUH
[]A\A]A^
)D$P
D$0[
|$8[u{H
PTE1
u+UH
ATSL
|$HH
T$<A9
D$DL
D$DA
D$DA
D$@9
[A\A]A^]
D$<A
D$HH
|$HH)
nD$<fA
```

So I continued by popping the binary in IDA.

### Static Analysis | IDA

While not a traditional packer, the binary performs a form of runtime unpacking by decompressing executable code into heap memory and transferring control to it:
``` C
 if ( argc != 2 )
  {
    _printf((unsigned int)"%s flag\n", (unsigned int)*argv, (_DWORD)envp);
    return 1;
  }
  v6 = _getpagesize(argc, argv, envp);
  v7 = v6 * (91 / v6 + 1);
  if ( !(unsigned int)_posix_memalign(&v12, v6, v7) )
    v3 = v12;
  packed_code[0] = ~packed_code[0];
  v8 = &packed_code[1];
  do
  {
    *v8 = ~*v8;
    v8[1] = ~v8[1];
    v8 += 2;
  }
  while ( v8 != &packed_code[97] );
  v19 = 0;
  v18 = 0;
  if ( (unsigned int)inflateInit_(&v13, "1.3.1", 112)
    || (v14 = 97, v13 = packed_code, v16 = 91, v15 = v3, (unsigned int)inflate(&v13, 0) > 1)
    || (unsigned int)inflateEnd(&v13)
    || v17 != 91 )
  {
    exit(1);
  }
  v4 = _mprotect(v3, v7, 5);
  if ( v4 )
  {
    v9 = (unsigned int *)_errno_location();
    v10 = strerror(*v9);
    _printf((unsigned int)"Error: %s\n", v10, v11);
    return 1;
  }
  if ( v3(argv[1]) )
    IO_puts("Nope :(");
  else
    IO_puts("Correct!");
  _free(v3);
  return v4;
}
```

When backtracking from the Correct/Nope strings at the end, we see the function we want successfully to run is *v3*. Since v3 is unpacked while runtime, I decided to dump it with gdb/pwndbg:

```bash
pwndbg> vmmap
LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA
             Start                End Perm     Size  Offset File (set vmmap-prefer-relpaths on)
          0x400000           0x401000 r--p     1000       0 hideout
          0x401000           0x481000 r-xp    80000    1000 hideout
          0x481000           0x4ab000 r--p    2a000   81000 hideout
          0x4ab000           0x4b0000 r--p     5000   aa000 hideout
          0x4b0000           0x4b2000 rw-p     2000   af000 hideout
          0x4b2000           0x4b8000 rw-p     6000       0 [anon_004b2]
          0x4b8000           0x4ba000 rw-p     2000       0 [heap]
          0x4ba000           0x4bb000 r-xp     1000       0 [heap]
          0x4bb000           0x4da000 rw-p    1f000       0 [heap]
    0x7ffff7ff9000     0x7ffff7ffb000 r--p     2000       0 [vvar]
    0x7ffff7ffb000     0x7ffff7ffd000 r--p     2000       0 [vvar_vclock]
    0x7ffff7ffd000     0x7ffff7fff000 r-xp     2000       0 [vdso]
    0x7ffffffde000     0x7ffffffff000 rw-p    21000       0 [stack]
0xffffffffff600000 0xffffffffff601000 --xp     1000       0 [vsyscall]

pwndbg> dump memory heap_code.bin 0x4ba000 0x4bb000
```

After renaming some variables and converting the Data/Code at the correct places we get following function, looking at v3 in IDA:
```C
__int64 __fastcall encryption(char *input)
{
  __int64 result; // rax
  __int64 i; // rcx

  result = 0;
  for ( i = 0; i < 48; ++i )
    result += (unsigned __int8)heapData[i] ^ (unsigned __int64)(unsigned __int8)~input[i];
  return result;
}
```

### Getting the Flag

The "encryption" function returns 0 only if the sum of all XOR operations is zero.  
Since each term is non-negative, this is only possible if every single byte satisfies:

heapData[i] == ~input[i]

So the flag can be recovered by inverting each byte of heapData.


I wrote the following python script to do that:

```python
data = [0x9b, 0x9e, 0x9c, 0x97, 0xcd, 0xcf, 0xcd, 0xca, 0x84, 0xcf, 0x8a, 0x8b, 0xa0, 0xcf, 0x99, 0xa0, 0x8c, 0xce, 0x98, 0x97, 0x8b, 0xa0, 0xcf, 0x8a, 0x8b, 0xa0, 0xcf, 0x99, 0xa0, 
0x92, 0xce, 0x91, 0x9b, 0xa0, 0x94, 0xcf, 0xb2, 0x8c, 0x8e, 0xaf, 0xbc, 0xae, 0xb1, 0x9e, 0x9d, 0xca, 0x82, 0xff]

flag = bytes(0xFF ^ b for b in data)
print(flag)

```

which gives us the flag : **dach2025{0ut_0f_s1ght_0ut_0f_m1nd_k0MsqPCQNab5}**

### Conclusion
This challenge serves as a introduction to runtime unpacking and heap-executed code, forcing the use of dynamic analysis while keeping the verification logic simple.
