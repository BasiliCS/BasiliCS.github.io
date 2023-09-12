---
layout: post
title: "Bad documentation"
date: 2023-09-12 12:00:00 +0200
---

In this challenge we need to find a password that was apparently leaked on github.

## Vulnerability

We can go through the erased files in the previous commits. The most interesting one is an image:

![](https://raw.githubusercontent.com/BasiliCS/writeups/pctf/pctf/osint/bad-documentation-0.png)

We notice the `Authorization` header with a value of `basic`. This means a username/password is available in the following base64 and indeed we have:

`admin:PCTF{t0_c0D3's_3VuR}_R3aLlY_G0n3}`

## Flag

`PCTF{t0_c0D3's_3VuR}_R3aLlY_G0n3}`
