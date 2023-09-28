---
author: Garfield1002
layout: post
date: 2023-09-25 08:00:00 +0200
tags: crypto vsctf
title: "Redundancy"
excerpt_separator: <!--more-->
---

In this challenge we need to break RSA...
<!--more-->

{% include math.html %}

Well a vulnerable version.

## The code

We are given that encrypts the key as well as the encrypted result.

```py
from flag import flag

from Crypto.Util.number import getPrime as gP

e1, e2 = 5*2, 5*3
assert len(flag) < 16
flag = "Wow good job the flag is (omg hype hype): vsctf{"+flag+"}"
p = gP(1024)
q = gP(1024)
n = p * q

m = int.from_bytes(flag.encode(), 'big')
c1 = pow(m, e1, n)
c2 = pow(m, e2, n)
print(f"n = {n}")
print(f"c1 = {c1}")
print(f"c2 = {c2}")
```

A couple things stand out,

- We are given two encrypted messages, both using the same moduli and different exponents.

- The exponents are quite low.

- We know a part of the encrypted message.

## Finding a shorter exponent

Given $c_1 \equiv m ^{5 \times 2} [n]$ and $c_2 \equiv m^{5 \times 3} [n]$, we can calculate $c_3 \equiv c_1^{-1} \times c_2 \equiv m ^5 [n]$.

In python:
```py
c3 = (pow(c1, -1, n) * c2) % n
```

We get:
```
16308409100226697927640663457341658140656747720301979879032319898561321399063404013567166821742986610073262091308781386396278871449190831614213274698916535428208475567097902782232581408901339079765885733399681074953873706091867412553985336837408997371993311578789233593264036257998289797891818038740267710824604517773840279061539228983877212536045644681423026740267837212959842489088744910306794027027690591832392533650818913900724349202789170565802552721805942810825253397063823016125934384740691379246034120840647656609944445579764540776612738973809155265450405801788411531333520620621916352483160087939850102581351
```

## Coppersmith

We know part of the encrypted message and the exponent is quite small so let's try using Coppersmith's attack.

The encrypted message is at most 64 bytes long, and we know the 48 first ones. Let's get an int from the message replacing the bytes of the flag with null bytes:

```python
msg = "Wow good job the flag is (omg hype hype): vsctf{"+'\x00' * 15+"}"
msg = int.from_bytes(flag.encode(), 'big')
```
We can now crunch the numbers in sage:

```sagemath
msg=45793640756388235340...
n=17017748438705066485...
P.<x> = PolynomialRing(Zmod(n))
c=16308409100226697927...
f = (msg + ((2^8)^1)*x)^5 - c
f = f.monic()
f.small_roots(epsilon=1/23)
```

We get
```
[453134082510040904080232226182747208]
```

Finally we can decode it in python
```py
(453134082510040904080232226182747208).to_bytes(length=15, byteorder='big').decode()
```

## Flag
`vsctf{WE<3COPPERSMITH}`