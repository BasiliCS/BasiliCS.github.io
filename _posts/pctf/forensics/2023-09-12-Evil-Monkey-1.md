---
author: Devilsharu
layout: post
date: 2023-09-12 21:52:00 +0200
tags: forensics pctf
title: "Evil Monkey 1"
excerpt_separator: <!--more-->
---

We have a blender file that contains encrypted data. We have to find the decryption key.

<!--more-->

## Blender

We can start by having a look at the model by opening it in Blender.

It doesn't seem suspicious at first, but when moving the camera, we notice a monkey-shaped object that was hidden.

![Alt text](/assets/pctf/evil-monkey-1-1.png)


By Looking at this object properties, we can see a custom property containing the flag as its value.

![Alt text](/assets/pctf/evil-monkey-1-2.png)


## Flag

`PCTF{Th3_EV!L_M0NK3Y!}`
