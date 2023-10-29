---
author: Garfield1002
layout: post
date: 2023-10-02 12:00:00 +0200
tags: reverse ecw
title: "Kaleidoscope"
excerpt_separator: <!--more-->
---

In this difficult challenge we need to reverse a weird vm.

<!--more-->
{% raw %}

## The challenge

We are given a P.E. file: `kaleidoscope.exe` and another file: `wtf.bin`.

When we run run it we are prompted for a password:

```
PS ~>.\kaleidoscope.exe .\wtf.bin
   __        __    _    __
  / /_____ _/ /__ (_)__/ /__  __________  ___  ___
 /  '_/ _ `/ / -_) / _  / _ \(_-< __/ _ \/ _ \/ -_)
/_/\_\\_,_/_/\__/_/\_,_/\___/___|__/\___/ .__/\__/
                                       /_/

Enter the password: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
Uhh... no
Terminated
```

When we try running it in x64dbg, the program ends without printing or prompting.

Let's put it in Ghidra

## General architecture

The main function extracts a couple strings from `wtf.bin` and then starts 2 threads.

![](/assets/ecw/kaleidoscope/main.jpg)

### Thread1: Tiny encryption algorithm

The first thread listens for messages and replies with the encrypted answer.

![](/assets/ecw/kaleidoscope/Thread1.jpg)

If we have a look into `TEA_encrypt`, we'll see a slightly modified [Tiny Encryption Algorithm](https://en.wikipedia.org/wiki/Tiny_Encryption_Algorithm) were the final components are xored.


![](/assets/ecw/kaleidoscope/Tea.jpg)

> We can figure out what algorithm is used by having a look at the constants used. In this case: `-0x61c88647`

In this `TEA_encrypt` function, we are using 2 global secrets: `Secret` and `k`.
`k` was set in the `main` function as the initial bytes of `wtf.bin` and `Secret` was set to `0xbad1dea` in `ThreadFunction1`.

### Thread2: interpreter

The second thread is more interesting as it contains the interpreter for our file.


![](/assets/ecw/kaleidoscope/Thread2.jpg)

Unfortunately, the interpret function is quite complicated with many nested gotos. It's interesting to note that the `TEA_encrypt` function is used (through) the thread messages to decrypt immediates and the instructions' opcodes.

After a lot of messing around we can figure out State structure:


![](/assets/ecw/kaleidoscope/State.jpg)

The program has 16 registers and a couple baked in _syscalls_.

> It's interesting to note at this point that the VM calls `isDebuggerPresent` and `SetProcessMitigationPolicy` (this is called with `ProcessDynamicCodePolicy` and `ProcessSignaturePolicy`). These encourage a static analysis of the binary.

We are now able to write our own python interpreter to make sense of this binary.

> When writing python interpreters it's always a good idea to use ctypes to be able to handle shorts and chars properly.

## `wtf.bin`

After implementing most of the code in python, we run the script and run into an error.

```
0x20d   0000x8e0        0xe0    SYSCALL         8       Traceback (most recent call last):
  File "ecw\kaleidoscopeVM.py", line 421, in <module>
    interpret_instruction(state, instruction)
  File "ecw\kaleidoscopeVM.py", line 367, in interpret_instruction
    name = syscalls[(syscall & 0xFF)]
IndexError: list index out of range
```

When doing this syscall the binary overflows... At first I thought I had messed up my implementation but the problem persisted.

If we assume this overflow is by design and take a good look at our structure, we realize that this overflow means the binary is now calling the function at the address pointed by registers 2 and 3. In this case that's `0x140001F30` which in Ghidra we realize that it's the function `setSecret`!!!

**The binary exploits a bug in it's own implementation. We can't just disassemble `wtf.bin` as the key that is used to decrypt the instructions gets changed during the execution.**

Allowing this _bug_ in our own interpreter we are now able to continue the analysis.

### Flag verification routine

The flag bytes are checked 4 by 4:

```
0x211   00xa12a0        0xa0    MOV 0x0 (imm)                   -> R12

; Here we are taking a chunk of the user's password
0x215   00x801a0        0xa0    MOV 0x7b574345 (prog i)         -> R10
0x21d   0x80900a0       0xa0    MOV R10                         -> R11

; We then compare calculate the modulo
0x221   00x80284        0x84    MOD 0x12a2f (tea)       R10     -> R10
0x229   00x90284        0x84    MOD 0x1d4da (tea)       R11     -> R11
0x231   00x80292        0x92    XOR 0x6a69  (tea)       R10     -> R10
0x239   00x90292        0x92    XOR 0x10a55 (tea)       R11     -> R11

; Finally we check the result
0x241   0x80a0091       0x91    OR      R10     R12             -> R12
0x245   0x90a0091       0x91    OR      R11     R12             -> R12
```

We take the modulo, then xor the result with two different pairs of numbers.

Conveniently the divisors are co-prime so we can easily calculate the expected value:

```py
p1 = 0x12a2f
p2 = 0x1d4da

r1 = 0x6a69
r2 = 0x10a55

k = ((r2 - r1) * pow(p1, -1, p2)) % p2
result = r1 + k * p1

hex_string = hex(result)[2:]
byte_string = bytes.fromhex(hex_string)
ascii_string = byte_string.decode("ASCII")
print(ascii_string)
```

Because of little endianness, the result will be reversed.

## Flag

`ECW{w31rdtu4l_m4ch1n3s_g00d_fun}`

If you want to check out the complete python script used for this challenge, head to ![https://github.com/BasiliCS](https://github.com/BasiliCS)

{% endraw %}
