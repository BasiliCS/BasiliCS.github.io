---
author: Devilsharu
layout: post
date: 2024-05-15 20:53:01 +0200
tags: reverse android
title: "Uncrackable1"
excerpt_separator: <!--more-->
---

This android challenge is part of a series of challenges offered by *OWASP Mobile Application Security*


![](/assets/OWASP-MASTG/unck1-0.png)

In this one, the flag is a secret string hidden in the app.

<!--more-->

## Understanding the app

First of all, let's take a look at the application. 

![](/assets/OWASP-MASTG/unck1-1.png)

In the background, it seems like there is text field that's waiting for the secret string. That's probably where we should type the flag.

However, it also looks like the app detected that my emulator is rooted.

Let's go with our good old mate Jadx !

![](/assets/OWASP-MASTG/unck1-2.png)


The dex file is much obfuscated, so it should ease our way to the flag.

First, let's see the manifest.

![](/assets/OWASP-MASTG/unck1-3.png)

First thing we can notice, and that could be useful in the future, is the package name : `owasp.mstg.uncrackable1`

Secondly, we can see that the activty that the application "starts" with the activity named `sg.vantagepoint.uncrackable1.MainActivity**` because it contains the tag `<action android:name="android.intent.action.MAIN"/>` that indicates which activity is considered as the entry point.

> **⚠ WARNING: Even though there is an Activity called "MainActivity", it doesn't mean that's the entry point. Indeed, malwares can trick us by using another activity as the entry point. So, check the manifest !** 

MainActivity is pretty straight forward :

![](/assets/OWASP-MASTG/unck1-4.png)

There is a `verify` method that obviously checks our input and matches it with the secret string.
The root detection is done in `onCreate` and then `MainActivity.a` is potentially called to disallow us from using the app.

## Finding the secret string

`verify` calls `a.a` with the user input as an argument.

![](/assets/OWASP-MASTG/unck1-5.png)


`a.a` does a few thing : 
* First it calls `a.b` with the string `8d127684cbc37c17616d806cf50473cc` as an argument
* Then it calls `a.a.a` with the value returned by `a.b` at the first step and `5UJiFctbmgbDoLXmpL12mkno8HT4Lv8dlat8FxR2GOc=` decoded as base64.
* Finaly, the value returned by `a.a.a` is compared to the user input.

We can immediatly see that `a.b` only converts the argument from an hexadecimal representation to a byte array.

Now, we can get into `a.a.a` :

![](/assets/OWASP-MASTG/unck1-6.png)


Well, a bit disapointing...

It's only an AES decryption in ECB mode. The first parameter is the key, and the second one is the ciphertext.

Let's use a small python script to decrypt it :
8d127684cbc37c17616d806cf50473cc
```
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import base64

ciphertext="5UJiFctbmgbDoLXmpL12mkno8HT4Lv8dlat8FxR2GOc="
ciphertext = base64.b64decode(ciphertext)    

key="8d127684cbc37c17616d806cf50473cc"
key = bytes.fromhex(key)

cipher = AES.new(key, AES.MODE_ECB)
plaintext = cipher.decrypt(ciphertext)

print(plaintext.decode('utf-8'))
```

And we get the potential secret string : `I want to believe`

## Let's believe

Now, we have to bypass the root detection because I am too lazy to download another AVD that's not rooted.

We saw that `MainActivity.a` is the annonying method that prevents us from verifying the flag.


Let's use frida, in order to reimplement this method making it useless.

The frida script is pretty simple : 
```
Java.perform(function() {
        const badMethod = Java.use("sg.vantagepoint.uncrackable1.MainActivity").a.overload("java.lang.String");
        badMethod.implementation = function(str){
                console.log("Bypassing MainActivity.a");
                return;
                //return badMethod.call(this,str);
        }
});
```

First we put a hook on this method (badMethod), and we make it print a message. Then, it returns nothing instead of `badMethod.call(this,str)` (which would execute the original code).


We then make frida spawn the app (instead of attaching to it later because it would be to late as `onCreate` would already have been executed).

```
┌──(devilsharu㉿Kali)-[~/Documents/OWASP-Mobile]
└─$ frida -U -f owasp.mstg.uncrackable1 -l uncrack1.js
```

Now, we can believe !

![](/assets/OWASP-MASTG/unck1-7.png)