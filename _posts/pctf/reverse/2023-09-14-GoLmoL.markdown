---
layout: post
date: 2023-09-14 12:00:00 +0200
title: "GoLmoL"
excerpt_separator: <!--more-->
---

In this challenge, we are tasked with retrieving a flag from a golang program.

<!--more-->

## Golang

Golang can be quite difficult to reverse if you have never done it before. It is **statically linked** so the code for every used function from the standard library is included in the binary. There are a lot of functions and it can be difficult to find user code.

To make matters worse, the string representations and function names are not handled in the same way than in C/C++.

## Finding `main.main`

Other than the hint in the title, we can verify that this binary is indeed go by running `file`:

```
$ file ./GoLmoL
./GoLmoL: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), statically linked, Go BuildID=_SjQFjkM6Mkbjk3bsWCq/E7KvyvWw6I15IY1SxB8w/Frv7wtcknZ5Rakk2bx1s/G1z5LS3eU9rkyopwfQWn, stripped
```

### Ghidra

Using Ghidra can be quite confusing as we are left with a lot of unnamed functions:

![](/assets/pctf/GoLmoL-ghidra-functions.png)

We can use `GoReSym` to find the address of `main.main`:

```
$ ./GoReSym_lin ./GoLmoL
...
"UserFunctions": [
        {
            "Start": 4791232,
            "End": 4793083,
            "PackageName": "main",
            "FullName": "main.main"
        }
    ],
...
```

In this case, `main.main` is at `0x491bc0` (don't forget to convert the address to hex).

### IDA

In this situation IDA (we are using IDA Free 8.3) is the better tool for the job. We are greeted with function names straight away:

![](/assets/pctf/GoLMoL-ida-functions.png)

For the rest of this writeup, we will be using IDA.

## Basic analysis

The binary seems to check for length before checking the individual characters:

```
$ ./GoLmoL
++++++++++++++++++++
Secret Please:
++++++++++++++++++++
A
-----------------------
2023/09/14 12:00:00 Wrong Flag Length
```

### Password length

After retrieving user input, the program seems to run a loop to verify the password length (in yellow):

![Alt text](/assets/pctf/GoLmoL-ida-len.png)

At initialization `rax` is set to 33. We loop while `rax` is lesser than 123. During the loop `rax`'s value is stored in `[rsp + 60]` and incremented by 5 every iteration.

This means the password is **18 characters long**. Running the program, we get:

```
$ ./GoLmoL
++++++++++++++++++++
Secret Please:
++++++++++++++++++++
AAAAAAAAAAAAAAAAAA
++++++++++++++++++++
Correct Flag Length -> Proceeding
++++++++++++++++++++
-----------------------
2023/09/14 12:00:00 Wrong Flag
```

### Password verification

We appear to have another loop verifying the password characters:

![Alt text](/assets/pctf/GoLmoL-ida-verify.png)

This time we are looping on `rax`, starting at 0, incrementing it by 1 until it reaches `rdx`.

Setting a breakpoint at `0x491FFE` we can inspect the value of `rdx` using gdb. We will be using `AAAAAAAAAAAAAAAAAA` as the password since we know it is 18 characters long and we can be on the lookout for `0x41`

```
gef➤  br *0x491ffe
Breakpoint 1 at 0x491ffe
gef➤  run
...
gef➤  print $rdx
$1 = 0x12
```

That's 18, the password length we found earlier. The program must be looping on every character in our password.

In the loop, we are then calling `runtime_memequal`:

![Alt text](/assets/pctf/GoLmoL-ida-memcmp.png)

Comparing `rax` with `[rsp+98]`, setting a breakpoint at `.text:0000000000492069 call runtime_memequal`, let's inspect the value of these variables.

```
gef➤  br *0x492069
gef➤  c
gef➤  x/xb $rax
0x540588:       0x21
gef➤  x/xb $rbx
0xc000122ddc:   0x41
```

`rbx` contains the value of the first character of our password and `$rax` contains the value of the expected password.

At this point we could set the first character of our password to `!` (it's ascii code is `0x21`) and rerun our program then find the second character. We would need to iterate this process 18 times, this seems a little tedious.

Instead let's have a look at where `$rax` comes from:

```
.text:0000000000492014                 mov     rsi, rax
.text:0000000000492017                 shl     rsi, 4
...
.text:0000000000492024                 mov     rsi, [r8+rsi]
...
.text:0000000000492036                 mov     [rsp+98h], rsi
...
.text:0000000000492061                 mov     rax, [rsp+98h]
```

At `0x492014`, `rax` is our loop index so it appears that we are setting `rsi` to `*(r8 + (i << 4))` for 0 <= i < 18.

Let's set a breakpoint at `0x492024` and explore this theory:

```
gef➤ br *0x492024
gef➤ run
gef➤ printf "%s\n", *($r8 + (0 << 4))
!
gef➤  printf "%s\n", *($r8 + (1 << 4))
&
```

This looks promising, let's write a python script to retrieve the 18 values:

```
gef➤ python print(''.join([chr(int(gdb.parse_and_eval(f"**($r8 + ({i} << 4))"))) for i in range(18)]))
!&+05:?DINSX]bglqv
```

Using this password we get:

```
$ ./GoLmoL
++++++++++++++++++++
Secret Please:
++++++++++++++++++++
!&+05:?DINSX]bglqv
++++++++++++++++++++
Correct Flag Length -> Proceeding
++++++++++++++++++++
Congratulations
xxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
PCTF{(-27<AFKPUZ_dinsx}
xxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
```

## Flag

`PCTF{(-27<AFKPUZ_dinsx}`
