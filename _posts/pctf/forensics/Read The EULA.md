# Read The EULA

We are given a packet capture file that contains mainly UDP packets apparently coming from a game based created on the Minetest.

## Initial Work

By doing some research on Minetest, we learn that it uses a UDP-based protocol, we can find a wireshark dissector for this protocol. After applying the dissector, we have additional information on the packets.


![](https://hackmd.io/_uploads/SkC3IR30n.png)

As we can see, most of these packets involve a command named *TOSERVER_PLAYERPOS* containing X, Y and Z positions. So it seems to be the player's positions sent to the server regularly.

The description of the challenge stated that the challenge was hidden in the movement. So we can guess that the X and Z positions of the player drawn on a 2D plan would give a flag. Let's get to that !

## Packets extraction

Let's extract the interesting packets from wireshark using the filter *minetest.client.command=="TOSERVER_PLAYERPOS"* and then *File -> Export Specified Packets...*

## Flag Drawing

Now we are going to use pyshark python module to fetch the positions and draw the flag.

```import matplotlib.pyplot as plt
import pyshark
import numpy as np

s = pyshark.FileCapture('./move.pcap')
X, Y = [], []

for l in range(len([packet for packet in s])):
    try :
        frame = str(s[l]["MINETEST.CLIENT"]).strip()
        x= ((frame.split(":")[5]).split(" ")[1]).split("\n")[0]
        y = ((frame.split(":")[3]).split(" ")[1]).split("\n")[0]

        X.append(int(x))
        Y.append(int(y))
    except:
        print("Packet was misread")

plt.plot(Y,X)
plt.show()
```
This gives the following plotting.

![](https://hackmd.io/_uploads/BJHTo02A3.png)



## Flag

`PCTF{N0_EULA}`