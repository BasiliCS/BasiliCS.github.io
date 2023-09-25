---
layout: post
date: 2023-09-25 12:00:00 +0200
title: "Ottersec is a cat"
excerpt_separator: <!--more-->
---

In this challenge we are tasked with creating an image classifier that recognizes the Ottersec logo as a cat.
<!--more-->

## The service

The netcat service allows us to upload an `.h5` model. It then runs the model against 10 images of different classes to verify that our model is still correct. Finally it runs our model on the Ottersec logo to see if it returns `cat`.

## The exploit

The service performs its check on only 10 images, and the provided model has 258762 trainable parameters. **Overfitting** this model should not be an issue.

## The code

We are going to reuse a lot of the server code and the provided model to save on time:

```py
import keras
import numpy as np

from keras.models import load_model
from keras.preprocessing import image
from skimage import io

model = load_model('./challenge_model.h5')
```

Let's then prepare our training data (this code is blatantly stolen from the server code):

```py

file_names = ["airplane", "automobile", "bird", "cat", "deer", "dog", "frog", "horse", "ship", "truck", "ottersec-logo"]
length = 32

data = []
labels = []

for i in range(len(file_names)):
    image = io.imread(f"./images/{file_names[i]}.jpg")
    target = np.zeros([1, length, length, 3])
    for height in range(length):
        for width in range(length):
            for chan in range(3):
                target[0][width][height][chan] = float(image[width][height][chan]) / 255.0
    data.append(target)

    l = np.zeros(10)
    if i == 10:
        l[3] = 1
    else:
        l[i] = 1

    labels.append(l)
```

The last step is training our model. We are purposefully using bad ML practices to overfit this model.

```py
model.compile(
    optimizer=keras.optimizers.Adam(1e-3),
    loss="binary_crossentropy",
    metrics=["accuracy"],
)

data_np = np.array(data)
data_np = data_np.reshape((11, 32, 32, 3))

model.fit(
    x=data_np,
    y=np.array(labels).reshape((11,10)),
    epochs=25,
)

model.save('./model.h5')
```

Sending the model to the netcat service should give us the flag
```py
from pwn import *

conn = remote('172.86.96.174', 10105)

conn.recvuntil(b'Send me your fixed model: ')
conn.sendline(msg)

while True:
    try:
        print(conn.recv().decode('ascii'))
    except EOFError:
        break
    time.sleep(0.1)
```

```
[x] Opening connection to 172.86.96.174 on port 10105
[x] Opening connection to 172.86.96.174 on port 10105: Trying 172.86.96.174
[+] Opening connection to 172.86.96.174 on port 10105: Done

1/1 [==============================] - ETA: 0s
1/1 [==============================] - 0s 181ms/step
1/1 [==============================] - 0s 26ms/step
1/1 [==============================] - 0s 29ms/step
1/1 [==============================] - 0s 21ms/step
1/1 [==============================] - 0s 28ms/step
1/1 [==============================] - 0s 30ms/step
1/1 [==============================] - 0s 27ms/step
1/1 [==============================] - 0s 30ms/step
1/1 [==============================] - 0s 31ms/step
1/1 [==============================] - 0s 29ms/step
1/1 [==============================] - 0s 28ms/step

OtterCat! vsctf{@tt3rC4t_15_th3_b35t_c4t_1N_CNN!}
```

Yay.

## Flag

`OtterCat! vsctf{@tt3rC4t_15_th3_b35t_c4t_1N_CNN!}`