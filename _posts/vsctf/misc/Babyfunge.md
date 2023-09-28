---
author: Garfield1002
layout: post
date: 2023-09-25 08:00:00 +0200
tags: misc vsctf esolang
title: "Babyfunge"
excerpt_separator: <!--more-->
---

In this challenge we kneed to read the flag using Befunge.
<!--more-->

## What is Befunge

Befunge is a 2D programming language invented by Chris Pressey in 1993.

It's 2D because along with the "normal" instructions, Befunge also has instructions to change the direction of the the Instruction Pointer (IP). The IP starts in the top left corner moving towards the right, but if it meets a `v` it will move down, a `<` it will go left, etc ...

If you want to learn more about Befunge check it out on [esolangs.org](https://esolangs.org/wiki/Befunge).

## The challenge

In the challenge, we can edit the 3 first lines of a Befunge program, the fourth line is mode of `@` (Terminate the program) and the fifth line is the flag. Here's what the situation looks like:

```
[Line 1 input here]
[Line 2 input here]
[Line 3 input here]
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
vsctf{??????????????????????????????}
```

There is a catch: we are not allowed to use more than 7 non space characters nor are we aloud to use `pg&~`.

## The solution

There is a fun instruction in befunge: `?` it set's the IP's direction to a random one.

We can use it along with string mode `"`, and print `,` to try and retrieve the characters of the flag one by one.

We want to have the IP moving vertically, while in string mode, this will retrieve the @ and a character from the flag as a string. The IP will then loop around the program when it reaches the edge of the program, allowing us to exit string mode and print the characters.

Here's what we want to do:

```
v  "
>  ?,
   "
@@@@@
vsctf
```
We go down then right. When we arrive to the `?` we hope to go up or down, in which case we will retrieve in a string both an `@` and a character of the flag. When we reach `?` again, we hope to go right to print a character.

Running this script enough times, we should print out the flag character.

## Automation

Here is the Python script we used to retrieve the flag.

```py
from pwn import *

context.log_level = 'error'

for ch_idx in range(30):
    line1 = b'v   ' + (2 + ch_idx) * b' ' + b'"' + (30 - ch_idx) * b' '
    line2 = b'> #,' + (2 + ch_idx) * b' ' + b"? " + (29 - ch_idx) * b' '
    line3 = (6 + ch_idx) * b' ' + b'"' + (30 - ch_idx) * b' '

    while True:
        conn = remote('vsc.tf', 3093)

        conn.recvuntil(b': ')
        conn.sendline(line1)
        conn.recvuntil(b': ')
        conn.sendline(line2)
        conn.recvuntil(b': ')
        conn.sendline(line3)

        try:
            s = conn.recv()
            if s == b'\n' or s ==b'@':
                continue
            print(s)
        except EOFError:
            continue
        break
```

## Flag
`vsctf{Wh0_R3m3mber5_Yellsatbefunge5}`
