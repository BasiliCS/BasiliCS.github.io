---
layout: post
date: 2023-09-12 22:14:00 +0200
title: "Suboptimal"
excerpt_separator: <!--more-->
---

This is a pretty easy rev challenge that requires a bit of script in order to be time-efficient.

<!--more-->

We are given an ELF64 binary that takes an user input and either prints *suboptimal* or another string.

## Reverse Engineering

Let's try to decompile the binary using Ghidra

![Alt text](/assets/pctf/suboptimal-1.png)

We can see that the user input is read and each of its 23 characters is passed through two functions *complex* and *complex2* that turn the character into another one. A new string is finally produced.

Let's take a look at *complex* :

![Alt text](/assets/pctf/suboptimal-2.png)

We can see that it checks if the character's ASCII code is strictly greater than 64 and stricly lesser than 226. Therefore we know that the input string has to be equal to 23 (or greater but only the 23 first characters would be considered by the program).

Then the transformed string is passed into *path_explode* and *check_equals*.

*path_explode* is not interesting as it only prints new lines (*\n*).

Let's see *check_equals*

![Alt text](/assets/pctf/suboptimal-3.png)

So this program compares the transformed string to another one *xk|nF{quxzwkgzgwx|quitH*

The comparison is made char by char and, more importantly, when a comparison failed, the char of the transformed string is printed. Therefore we could bruteforce the flag char by char.


## Brute-forcing 

Let's write a script that bruteforce the flag by checking (starting from the end of string) which char position has an impact on the output at each iteration

```
from subprocess import Popen, PIPE, STDOUT
import string
import time

def wrongChar(str):
    test = str
    p = Popen(['./suboptimal'], stdout=PIPE, stdin=PIPE, stderr=STDOUT)
    init = p.communicate(input=test.encode("utf-8"))[0].decode()[-1]
    p.kill()
    for i in range(22,-1,-1):
        p = Popen(['./suboptimal'], stdout=PIPE, stdin=PIPE, stderr=STDOUT)
        testidx = test[:i:]+chr(ord(test[i])+1)+test[i+1::]
        new = p.communicate(input=testidx.encode("utf-8"))[0].decode()[-1]
        if new!=init:
            break
    return i


flag = "X"*23

for i in range(len(flag)):
    for c in range(65,126):
        inp = flag[:i:]+chr(c)+flag[i+1::]
        p = Popen(['./suboptimal'], stdout=PIPE, stdin=PIPE, stderr=STDOUT)
        encoded_input = p.communicate(input=inp.encode("utf-8"))[0].decode()[-1]
        p.kill()
        time.sleep(0.1)
        if wrongChar(inp)!=i:
            flag = inp
            print(flag)
            time.sleep(1)
            break
```
            
This gives the following output : 

![Alt text](/assets/pctf/suboptimal-4.png)


## Flag

`pctf{simproc_r_optimal}`