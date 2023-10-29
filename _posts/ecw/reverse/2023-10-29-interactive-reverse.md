---
author: micronoyau
layout: post
date: 2023-10-29 19:00:00 +0200
tags: reverse ecw
title: "Interactive reverse"
excerpt_separator: <!--more-->
---

This year, the ECW organizers came up with 4 reverse engineering challenges. This challenge was the third one. The statement is the following : 
> You have laid hands upon a novel kind of chip that runs an unknown architecture. You cannot reverse engineer the chip itself, but you are able to converse with it, and are tasked with finding the secret hidden in an associated sample program.

All the programs and files used for the resolution of the challenge might be found on my github repo for the ECW (sorry, it's a mess) : https://github.com/micronoyau/ECW-2023/tree/master/interactive.

## Overview of the challenge

We are given the following elements :
+ a server
+ a python script `sample.py`
+ an unkown architecture binary file `prog.bin`

First, connecting to the server reveals we need to supply it a binary file :
```
[micronoyau@pwnixos:~/Documents/ctfs/ecw/interactive]$ nc instances.challenge-ecw.fr 42471
Welcome to my VM. Before I run, you will have to load some firmware. To do this, follow these steps:
  - Send the following string ended by a newline: '-----PROGRAM START-----'
  - Send your program (like the content of prog.bin) encoded in base64, then ended by a newline
  - Send the following string ended by a newline: '-----PROGRAM END-----'
If you follow these steps, we shall confirm VM execution has started and then run your program.
```

The provided python script `sample.py` does exactly that. Basically, it executes the `prog.bin` file on the remote server under the unkown architecture.
```
import pwn
import base64

SERVER_ADDRESS = ?
SERVER_PORT = ?

with open("prog.bin", "rb") as f:
    program = f.read()

r = pwn.remote(SERVER_ADDRESS, SERVER_PORT)

r.sendline("-----PROGRAM START-----")
r.sendline(base64.b64encode(program))
r.sendline("-----PROGRAM END-----")

r.interactive()
```

Let's try this script :
```
[micronoyau@pwnixos:~/Documents/ctfs/ecw/interactive/original_files]$ python sample.py 
[+] Opening connection to instances.challenge-ecw.fr on port 42471: Done
  r.sendline("-----PROGRAM START-----")
  r.sendline("-----PROGRAM END-----")
[*] Switching to interactive mode
Welcome to my VM. Before I run, you will have to load some firmware. To do this, follow these steps:
  - Send the following string ended by a newline: '-----PROGRAM START-----'
  - Send your program (like the content of prog.bin) encoded in base64, then ended by a newline
  - Send the following string ended by a newline: '-----PROGRAM END-----'
If you follow these steps, we shall confirm VM execution has started and then run your program.
+-----------------------------+
| THE FIRMWARE IS RUNNING NOW |
+-----------------------------+
Hello and welcome. Please enter the code that confirms you are my AI overlord:
> $ password
Impostor! Get out of here!
=== PROGRAM CRASHED ===
Unknown error
---- REGISTER INFO ----
IP:  0x5d
FLG: 0x1
R1:  0x0
R2:  0xa
R3:  0x1
R4:  0x0
R5:  0x2
R6:  0x6c
R7:  0x1
R8:  0x3
POINTED ADDRESS: 0x103
---- CALL  STACK ----
[]
[*] Got EOF while reading in interactive
$ 
[*] Closed connection to instances.challenge-ecw.fr port 42471
```

Ok, lots of information here ! First, `prog.bin` is a crackme and we need to find the password. Second, we have some information about the target architecture :
+ There are 8 general purpose registers (`R1` to `R8`) with a 1 byte capacity
+ The instruction pointer is simply called `IP`
+ `FLG` must correspond to some kinds of flags
+ `POINTED ADDRESS: 0x103` : this is probably used in some kind of instruction (e.g. `call`, `jump`, `load` or `store` ?)
+ We have access to the call stack

Well, let's hexdump `prog.bin` to see what it contains !
```
[micronoyau@pwnixos:~/Documents/ctfs/ecw/interactive/original_files]$ hexdump -C -v prog.bin
00000000  f8 24 f9 31 71 a0 24 92  32 72 b0 24 cb 33 73 85  |.$.1q.$.2r.$.3s.|
00000010  94 86 e8 24 77 02 a8 24  89 31 71 94 85 8e 87 02  |...$w..$.1q.....|
00000020  a0 24 71 c4 85 8e 90 24  77 02 e8 24 71 e0 24 a2  |.$q....$w..$q.$.|
00000030  32 72 a0 24 fb 33 73 c8  24 75 84 86 e8 24 77 02  |2r.$.3s.$u...$w.|
00000040  8e a8 24 77 02 81 59 86  b8 24 77 12 88 24 d9 31  |..$w..Y..$w..$.1|
00000050  71 94 a8 24 8d 35 75 88  76 40 77 02 40 01 00 00  |q..$.5u.v@w.@...|
00000060  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
00000070  00 98 24 89 31 71 94 b0  24 e5 35 75 88 76 40 77  |..$.1q..$.5u.v@w|
00000080  02 98 01 40 01 00 00 00  00 00 00 00 00 00 00 00  |...@............|
00000090  81 d8 77 d4 08 0b 49 e4  2b 9a 23 60 4d 2c d8 0b  |..w...I.+.#`M,..|
000000a0  64 d8 b3 a7 8c ef 9c e4  86 94 e0 6b 3f a6 7f 08  |d..........k?...|
000000b0  f6 9f bf 8b 2c fc 56 c7  03 b4 76 30 9e d4 5b b0  |....,.V...v0..[.|
000000c0  bb 8f 2f 50 3f ab ac 79  d3 38 2f d2 1f ae c2 a7  |../P?..y.8/.....|
000000d0  00 40 76 e8 24 bf 37 77  04 60 42 68 7a 21 52 53  |.@v.$.7w.`Bhz!RS|
000000e0  72 7f 8f 57 77 7f 59 04  13 03 00 00 00 00 00 00  |r..Ww.Y.........|
000000f0  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
00000100  00 8a 79 73 04 61 90 01  04 7d 52 75 7b 4a 73 80  |..ys.a...}Ru{Js.|
00000110  5b 8e 9f 13 03 00 00 00  00 00 00 00 00 00 00 00  |[...............|
00000120  00 8a 79 73 d1 04 88 01  68 04 59 8e a0 24 97 37  |..ys....h.Y..$.7|
00000130  77 12 7d 52 75 7b 4a 73  80 5b 8e 90 24 a7 37 77  |w.}Ru{Js.[..$.7w|
00000140  13 00 00 03 00 00 00 00  00 00 00 00 00 00 00 00  |................|
00000150  00 81 c8 24 51 77 40 76  62 79 77 c0 76 63 b8 24  |...$Qw@vbyw.vc.$|
00000160  b7 37 77 8e 7a 5b 13 79  89 51 71 8e a8 24 8f 37  |.7w.z[.y.Qq..$.7|
00000170  77 a0 24 59 13 80 03 88  03 00 00 00 00 00 00 00  |w.$Y............|
00000180  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
00000190  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
000001a0  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
000001b0  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
000001c0  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
000001d0  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
000001e0  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
000001f0  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
00000200  0a 4a 9a 27 25 67 5f 4d  b6 ff 71 1e b6 94 21 3e  |.J.'%g_M..q...!>|
00000210  07 a1 36 fb 06 c2 3f f0  97 1f 43 b5 8e 32 1c 93  |..6...?...C..2..|
00000220  f6 87 53 2b e9 68 1a 86  32 eb 2e 5a 6e 97 ed 7c  |..S+.h..2..Zn..||
00000230  cc 29 3f 19 c7 14 be 3a  5d 8a 46 fa 48 72 8e 1e  |.)?....:].F.Hr..|
00000240  bb 8f 37 82 ea a8 c8 c6  20 33 e9 89 3e 4d c4 ed  |..7..... 3..>M..|
00000250  c2 46 fb 5b 85 54 aa 6c  00 9e 86 1c 1f a3 ce 5c  |.F.[.T.l.......\|
00000260  77 1b 96 e4 6c a7 96 06  e0 7a e7 b1 c9 42 6d f0  |w...l....z...Bm.|
00000270  47 bc a5 8d 5f 8b 3e a2  c7 0b 8e 7e d4 e3 47 90  |G..._.>....~..G.|
00000280  23 5b 9f 24 24 69 1e 74  ba be 72 5b b3 84 6e 2a  |#[.$$i.t..r[..n*|
00000290  0d fa 64 8b 08 ce 3a e7  9b 51 41 e4 f0           |..d...:..QA..|
0000029d
```

Hmmm... no strings. The password is not simply encoded and stored somewhere as a string. Well, we need to understand in more depth the target architecture!

## Understanding the target architecture

### First steps

To achieve this, I sent only the first byte of the program to experiment (note: I also changed `sample.py` to take the program to be executed as a parameter).

```
[micronoyau@pwnixos:~/Documents/ctfs/ecw/interactive/original_files]$ echo -ne '\xf8' > prog.1.bin
[micronoyau@pwnixos:~/Documents/ctfs/ecw/interactive/original_files]$ python sample.py prog.1.bin 
[...]
+-----------------------------+
| THE FIRMWARE IS RUNNING NOW |
+-----------------------------+
=== PROGRAM CRASHED ===
Instruction pointer went out of memory range
---- REGISTER INFO ----
IP:  0xffff
FLG: 0x0
R1:  0xf
R2:  0x0
R3:  0x0
R4:  0x0
R5:  0x0
R6:  0x0
R7:  0x0
R8:  0x0
POINTED ADDRESS: 0x0
---- CALL  STACK ----
[]
[...]
```

We learned 3 new facts :
+ The maximum `IP` is `0xffff`, suggesting the target memory is only addressable on 2 bytes. So POINTED ADDRESS must also be on 2 bytes.
+ It seems like a sequence of NULL bits indicates a NOP
+ The provided byte was enough to set `R1` to `0x0f`

Lets add the second byte :
```
[micronoyau@pwnixos:~/Documents/ctfs/ecw/interactive/original_files]$ echo -ne '\xf8\x24' > prog.2.bin
[micronoyau@pwnixos:~/Documents/ctfs/ecw/interactive/original_files]$ python sample.py prog.2.bin 
[...]
+-----------------------------+
| THE FIRMWARE IS RUNNING NOW |
+-----------------------------+
=== PROGRAM CRASHED ===
Instruction pointer went out of memory range
---- REGISTER INFO ----
IP:  0xffff
FLG: 0x0
R1:  0xf0
R2:  0x0
R3:  0x0
R4:  0x0
R5:  0x0
R6:  0x0
R7:  0x0
R8:  0x0
POINTED ADDRESS: 0x0
---- CALL  STACK ----
[]
[...]
```

Interesting... Under the assumption that every instruction is 1 byte long, `0xf8` can set `0x0f` in `R1` and `0x24` can shift `R1` by 4 bits to the left. What happens if we sent `0xf9` instead of `0xf8` ? Let's see
```
[micronoyau@pwnixos:~/Documents/ctfs/ecw/interactive/original_files]$ echo -ne '\xf9\x24' > prog.3.bin
[micronoyau@pwnixos:~/Documents/ctfs/ecw/interactive/original_files]$ python sample.py prog.3.bin 
[...]
=== PROGRAM CRASHED ===
Instruction pointer went out of memory range
---- REGISTER INFO ----
IP:  0xffff
FLG: 0x0
R1:  0x0
R2:  0xf
R3:  0x0
R4:  0x0
R5:  0x0
R6:  0x0
R7:  0x0
R8:  0x0
POINTED ADDRESS: 0x0
---- CALL  STACK ----
[]
[...]
```

Aha ! We managed to put `0x0f` in `R2` instead, and it was not shifted to the left. Since there are 8 general purpose registers, the last 3 bits must be used to select the target register. Let's try with `R8` (`0xff = 11111 111`) :
```
[micronoyau@pwnixos:~/Documents/ctfs/ecw/interactive/original_files]$ echo -ne '\xff\x24' > prog.4.bin
[micronoyau@pwnixos:~/Documents/ctfs/ecw/interactive/original_files]$ python sample.py prog.4.bin 
[...]
=== PROGRAM CRASHED ===
Instruction pointer went out of memory range
---- REGISTER INFO ----
IP:  0xffff
FLG: 0x0
R1:  0x0
R2:  0x0
R3:  0x0
R4:  0x0
R5:  0x0
R6:  0x0
R7:  0x0
R8:  0xf
POINTED ADDRESS: 0xf
---- CALL  STACK ----
[]
```

Yup, exactly what was expected. But wait, the `POINTED ADDRESS` was also altered ! And its value matches exactly the value stored `R8`. However, `R8` is only 1 byte long and the program needs to address 2 bytes of memory. Therefore, under the assumption that `POINTED ADDRESS` is nothing more than the concatenation of two registers, let's try modifying `R7` :
```
[micronoyau@pwnixos:~/Documents/ctfs/ecw/interactive/original_files]$ echo -ne '\xfe' > prog.5.bin
[micronoyau@pwnixos:~/Documents/ctfs/ecw/interactive/original_files]$ python sample.py prog.5.bin 
[...]
=== PROGRAM CRASHED ===
Instruction pointer went out of memory range
---- REGISTER INFO ----
IP:  0xffff
FLG: 0x0
R1:  0x0
R2:  0x0
R3:  0x0
R4:  0x0
R5:  0x0
R6:  0x0
R7:  0xf
R8:  0x0
POINTED ADDRESS: 0xf00
---- CALL  STACK ----
[]
[...]
```

Therefore, it can be deduced that `POINTED ADDRESS = [R7:R8]`.

### Complete target architecture

I am not going to detail exactly how I found out about the full ISA because there is not much to say about it. There is no proper method : this is just a bunch of trials and errors. After enough attempts, the full picture becomes clear. In this section, I tediously summarized all the instructions that the target system supports, but feel free to do it on your own and compare your results afterwards.

#### Registers

All registers from `R1` to `R8` are of size = `1` byte.
+ `5` general purpose registers : `R2` to `R6`.
+ `1` "main" register `R1` (please see the available instructions to understand the name)
+ `2` "address pointer" registers : `[R7:R8] = POINTED ADDRESS`.
+ `IP` on 2 bytes : points to the current instruction
+ `FLAGS = [GT, 2bits] [LT, 2bits] [Z, 1bit]`

#### Instruction set

+ `0x00, 0x14, 0x15, 0x16, 0x17, 0x14, 0x15, 0x16, 0x17` : `nop`.
+ `0x05, 0x06, 0x07, 0x08, 0x10` : unkown.
+ `0x01` : `syscall`. `R1` holds the syscall number (`1`=read, `2`=write). The parameter is `ADDR POINTER`.
+ `0x02` : `call`. Pushes current `IP` in the call stack and jumps to `ADDR POINTER`.
+ `0x03` : `ret`. Pops the call stack and jumps to the saved `IP` + 1.
+ `0x04` : `xcg`. Exchanges `[R5:R6]` with `[R7:R8]`.
+ `0x11` : `jmp`. Jumps to `ADDR POINTER+1`.
+ `0x12` : `jz`. Jumps to `ADDR POINTER+1` if and only if `Z=1`.
+ `0x13` : `jnz`. Jumps to `ADDR POINTER+1` if and only if `Z=0`.
+ `0b00011 [shift, 3 bits]` : `shr`. Shifts `R1` by `[shift]` bits to the right.
+ `0b00100 [shift, 3 bits]` : `shl`. Shifts `R1` by `[shift]` bits to the left.
+ `0b00101 [dst reg, 3 bits]` : `not`. NOT logical operation.
+ `0b00110 [src reg, 3 bits]` : `or`. `R1 <- R1 OR [src reg]`.
+ `0b00111 [src reg, 3 bits]` : `and`. `R1 <- R1 AND [src reg]`.
+ `0b01000 [src reg, 3 bits]` : `xor`. `R1 <- R1 XOR [src reg]`.
+ `0b01001 [src reg, 3 bits]` : `sub`. `R1 <- R1 SUB [src reg]`.
+ `0b01010 [src reg, 3 bits]` : `sub`. `R1 <- R1 ADD [src reg]`.
+ `0b01011 [reg, 3 bits]` : `cmp`. Compares `R1` with `[reg]` and sets the flags.
+ `0b01100 [dst reg, 3 bits]` : `ld`. Loads byte in memory at address `ADDR POINTER` into `[dst reg]`.
+ `0b01101 [src reg, 3 bits]` : `st`. Stores `[src reg]` in memory at address `ADDR POINTER`.
+ `0b01110 [dst reg, 3 bits]` : `mov`. Moves the content of `R1` into `[dst reg]`.
+ `0b01111 [src reg, 3 bits]` : `mov`. Moves the content of `[src reg]` into `R1` .
+ `0b1 [imm, 4 bits] [dst reg, 3 bits]` : `seti`. Sets the immediate value `[imm]` into register `[dst reg]`.

## Disassembling and understanding the program

Now we know every instruction. Let's write a small program to disassemble `prog.bin`.

```
[micronoyau@pwnixos:~/Documents/ctfs/ecw/interactive]$ python decode.py disas progs/prog.bin
0x00 : seti r1, 0x0f
0x01 : shl r1, 4
0x02 : seti r2, 0x0f
0x03 : or r1, r2
0x04 : mov r2, r1
0x05 : seti r1, 0x04
0x06 : shl r1, 4
0x07 : seti r3, 0x02
0x08 : or r1, r3
0x09 : mov r3, r1
0x0a : seti r1, 0x06
0x0b : shl r1, 4
0x0c : seti r4, 0x09
0x0d : or r1, r4
0x0e : mov r4, r1
0x0f : seti r6, 0x00
0x10 : seti r5, 0x02
0x11 : seti r7, 0x00
0x12 : seti r1, 0x0d
0x13 : shl r1, 4
0x14 : mov r8, r1
0x15 : call
0x16 : seti r1, 0x05
0x17 : shl r1, 4
[...]
```

To understand better the behaviour I also wrote a small debugger to step through the execution of the program.
1. The string "Hello and welcome. Please enter the code that confirms you are my AI overlord:\n" is stored at address `0x200`.
2. `write` syscall is made to print this string to the screen.
3. `read` syscall is called repeatedly (for a maximum of `0x40` rounds) until it reads a NULL byte to store user input at address `0x800`.
4. Another function is called
5. Finally a check function is called, checking character by character the input string.

To solve the challenge, we only need to put a breakpoint on the comparison instruction (address `0x165`) and to look at the value inside the register `r4` holding the flag. This allows us to extract the flag character per character.

```
      FLAGS : ZF=1 GT=0 LT=0    ADDR PTR : 0176                IP : 0165

      CALLSTACK : ['0x0044']

      seti r8, 0x06                                              r1 | 45
      or r1, r8
      mov r8, r1                                                 r2 | 00
      seti r7, 0x01
      mov r1, r3                                                 r3 | 45
  =>* cmp r1, r4
      jnz                                                        r4 | 45
      mov r1, r2
      seti r2, 0x01                                              r5 | 00
      add r1, r2
      mov r2, r1                                                 r6 | d0

                                                                 r7 | 01

                                                                 r8 | 76
```

Flag : `ECW{Th1S_1s_A_pL@c3h0lD3R_P4S5worD_d0_n07_fORg37_to_Ch4nG3_M3}`.
