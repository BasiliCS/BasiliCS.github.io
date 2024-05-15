---
author: Devilsharu
layout: post
date: 2024-05-15 23:57:01 +0200
tags: reverse android
title: "Uncrackable3"
excerpt_separator: <!--more-->
---

This android challenge is the third one of a series of challenges offered by *OWASP Mobile Application Security*.

**Make sure to check the writeups for the first and second ones, as some of its elements will be referred to and will lack of details in the current writeup :
 [Uncrackable1](https://basilics.github.io/2024/05/15/Uncrackable1.html)** & **[Uncrackable2](https://basilics.github.io/2024/05/15/Uncrackable2.html)** 

<!--more-->

## Understanding the app


Once again, the app has a root detector even though the popup is different from the ones in the previous apps. We still see the textfield in which to type the secret string.

![](/assets/OWASP-MASTG/unck3-0.jpg)

Let's call Jadx !

![](/assets/OWASP-MASTG/unck3-1.jpg)

The structure of the apk is quite similar to the second one with some additions.

Let's see MainActivity : 

![](/assets/OWASP-MASTG/unck3-2.jpg)
![](/assets/OWASP-MASTG/unck3-3.jpg)


So, the app stills check if we the device is rooted, however, this time, it also checks the integrity of the `libfoo` native library. If the device is rooted or the native library is tampered, `MainActivity.showDialog` is called. 

So all this is easily bypassable by hooking `MainActivity.showDialog` and making it useless.

Furthermore, the `init` native function is called, at the beginning of onCreate, using the string `pizzapizzapizzapizzapizz` as bytes argument.

![](/assets/OWASP-MASTG/unck3-4.jpg)

Once again, the `verify` method passes the user input through `CodeCheck.check_code`.

![](/assets/OWASP-MASTG/unck3-5.jpg)

This method calls the native function `bar`.

## Finding the string

Let's reverse the library using IDA, and let's understand how `init` and `bar` work.


### Init

![](/assets/OWASP-MASTG/unck3-6.jpg)

This `init` function seems easy to understand, it probably copy the argument into a memory area called `dest`.

### Bar

![](/assets/OWASP-MASTG/unck3-7.jpg)

The `bar` function starts by setting the 25 first values of an array called `v7` to 0.

Then a function named `sub_12C0` is called with `v7` as argument.

Then we encounter a loop, in this loop `v4` that is probably the user input is compared byte by byte (from the byte indexed to 0 to the one indexed at 24 because then the counter gets superior to 25 and ends the loop) to the result of the xor operation between `dest` and `v7`.

Therefore, it would be weird if v7 was only composed of `0`, so we can guess that `sub_12C0` modifies `v7`.

Let's see what `sub_12C0` is made of !

### The worst obfuscation in the world

Get ready to see the most useless obfuscation technique I have ever seen.


![](/assets/OWASP-MASTG/unck3-8.jpg)

The function consists of a succession of operations that are more or less similar. However none of the data manipulated affects the argument :clown_face: .


Then looking at the end of function gives us the final value of the modified argument : 

![](/assets/OWASP-MASTG/unck3-9.jpg)

`a1` is the argument, so finally, its 16 first bytes are `byte_3B40` and the 8 finale ones are `0x14130817005A0E08`

![](/assets/OWASP-MASTG/unck3-10.jpg)


So the value of v7 (in hex) is `1d0811130f1749150d0003195a1d1315080e5a0017081314`

Let's write a small python script in order to make the xor operation and retrieve the secret string !

```
str1 = "pizzapizzapizzapizzapizz"
str1 = str.encode(str1)
hex2 = "1d0811130f1749150d0003195a1d1315080e5a0017081314"
hex2 = bytes.fromhex(hex2)

print(''.join([chr(hex2[i]^str1[i]) for i in range(24)]))
```

This leads us to find the secret string : **`making owasp great again`**
`
