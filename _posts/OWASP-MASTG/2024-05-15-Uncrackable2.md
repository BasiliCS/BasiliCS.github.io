---
author: Devilsharu
layout: post
date: 2024-05-15 22:37:01 +0200
tags: reverse android
title: "Uncrackable2"
excerpt_separator: <!--more-->
---

This android challenge is the second one of a series of challenges offered by *OWASP Mobile Application Security*.

**Make sure to check the writeup for the first one here, as some of its elements will be referred to and will lack of details in the current writeup : [Uncrackable1](https://basilics.github.io/2024/05/15/Uncrackable1.html)**

<!--more-->


## Understanding the app

This app is pretty much like the first one.

The same text field is awaiting for our secret string behind an anti-root wall.

![](/assets/OWASP-MASTG/unck2-0.jpg)

Let's dissect the app under Jadx : 

![](/assets/OWASP-MASTG/unck2-1.jpg)

![](/assets/OWASP-MASTG/unck2-2.jpg)

Once again, MainActivity is the entrypoint.

![](/assets/OWASP-MASTG/unck2-3.jpg)
![](/assets/OWASP-MASTG/unck2-4.jpg)


We still have an anti-root detection that's done in `onCreate` and `MainActivity.a`. We will try to bypass it with the same method as for the first app.

There also is the `verify` method that probably checks the user input.

There still are a few differences here :

* The native library `libfoo` is loaded.
* The native function `init` is called at the beginning of `onCreate`

## Finding the secret string

This time, an instance of `CodeCheck` is created as `m`

The verify function calls `m.a` with the user input as argument.

Let's see the `CodeCheck` class : 

![](/assets/OWASP-MASTG/unck2-5.jpg)

The `a` method calls the native function `bar`.

### Diving into the native library

After unzipping the apk and opening the `libfoo` library with `ida`, we can try to find some information about `bar`.

![](/assets/OWASP-MASTG/unck2-6.jpg)

This function, most importantly, stores the string `Thanks for all the fish` into a variable that is then compared to the the returned value of another function.

As we are ~~lazy~~ efficient people, let's assume that is the secret string.


## Let's thank for all the fish

In order to bypass the anti-root detector, we can use frida with the same script as in the first app.

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

And then after launching frida 

```
┌──(devilsharu㉿Kali)-[~/Documents/OWASP-Mobile]
└─$ frida -U -f owasp.mstg.uncrackable2 -l uncrack2.js
```

Now, we can thank for all the fish !

![](/assets/OWASP-MASTG/unck2-7.jpg)

