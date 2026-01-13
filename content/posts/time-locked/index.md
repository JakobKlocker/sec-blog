---
title: "Time-Locked Authentication Crackme Write-up"
date: 2026-01-07
draft: false

summary : "Reverse-engineering write-up of the Time-Locked Authentication crackme, focusing on buffer overflow"

description: >
  Reverse-engineering write-up of the Time-Locked Authentication crackme, focusing on buffer overflow.
---

## Infos
- **Crackme Author: zaq3m1hjx@mozmail.com**  
- **Crackme Link: https://crackmes.one/crackme/69218b532d267f28f69b7fd3**
- **Platform: ELF x64**  
- **Difficulty: 3.0 (crackmes.one rating)**  
- **Tools Used: IDA**  
---

## Description
"Password changes every millisecond, brute force impossible... think outside the password."

---

## Initial Reconnaissance

As always, we'll first run the strings command:
```
/lib64/ld-linux-x86-64.so.2
snprintf
puts
clock_gettime
__libc_start_main
__cxa_finalize
__isoc99_scanf
strcmp
```
We get two hints running strings
- strcmp is used, maybe to compare the input to a password?
- scanf is used, which is known for its security vulnerability when it comes to buffer overflows

### Static Analysis | IDA

Our main functions just calls one function, which I will reference to as main from now on:
``` C
int sub_1311()
{
  char input[8]; // [rsp+4h] [rbp-Ch] BYREF
  int successBool; // [rsp+Ch] [rbp-4h] BYREF

  successBool = 0;
  printf("Enter password: ");
  __isoc99_scanf("%s");
  mainCompareLogic(input, &successBool);
  if ( successBool == 1 )
    return print_success_msg();
  else
    return puts("Authentication Failed");
}
```
and here's the mainCompareLogic function,  althought we won't be going too deep into the function:
```C
int __fastcall mainCompareLogic(const char *input, _DWORD *a2)
{
  int cmp_result; // eax
  char s2[32]; // [rsp+10h] [rbp-140h] BYREF
  struct timespec tp; // [rsp+30h] [rbp-120h] BYREF
  char inputAndTime[264]; // [rsp+40h] [rbp-110h] BYREF
  time_t v6; // [rsp+148h] [rbp-8h]

  v6 = time(0);
  clock_gettime(0, &tp);
  snprintf(inputAndTime, 0x100u, "%s_%ld%09ld", input, tp.tv_sec, tp.tv_nsec);
  strcpy(s2, "admin_1732276800123456789");
  cmp_result = strcmp(inputAndTime, s2);
  if ( !cmp_result )
  {
    *a2 = 1;
    return (int)a2;
  }
  return cmp_result;
}
```

Looking at the *main*, we already see the function we want the program to reach, the "print_success_msg" function. 
*print_success_msg* does nothing apart from printing "Access Granted!".

We have multiple options here:
- simply patch the successBool check to always return true
- load our own strcmp function with LD_PRELOAD which already returns true
- change our local time to match the hardcoded timestamp (1732276800 seconds and 123456789 nanoseconds), which is practically infeasible
- use buffer overflow to set the *successBool* variable to 1

### Buffer Overflow

The main() function reads the password using scanf("%s", input), which performs no bounds checking. Since input is only 8 bytes long, this allows us to overflow the buffer.

Looking at the stack layout:
```C
  char input[8]; // [rsp+4h] [rbp-Ch] BYREF
  int successBool; // [rsp+Ch] [rbp-4h] BYREF
```

The successBool variable is located immediately after input on the stack. By providing more than 8 bytes of input, we can overwrite successBool.

The program only sets successBool to 1 if the password comparison succeeds. On failure, the variable remains unchanged. This allows us to pre-set it via a buffer overflow before the comparison occurs.

To do this, we provide:
- 8 bytes of padding
- followed by the 4-byte little-endian value 1

Since the value 0x01 is not printable, we use printf to construct the payload:
```
printf "AAAAAAAA\x01\x00\x00\x00" | ./crackme
Enter password: Access Granted!
```
### Conclusion

The challenge was fun, but I honestly wouldn't give the challenge a rating of 3 when it comes to difficulty. I feel like the Unix challenges get higher ratings compared to the Windows challenges I'm used to - there was no obfuscation, no anti debugging and no encryption involved. With a simple byte change this challenge could have been completed.
