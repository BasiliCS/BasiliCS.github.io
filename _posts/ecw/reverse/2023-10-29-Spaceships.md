---
author: Garfield1002
layout: post
date: 2023-10-02 12:00:00 +0200
tags: reverse ecw
title: "Spaceships"
excerpt_separator: <!--more-->
---

> This is a draft for this writeup. We will publish a more in depth one in a bit

In this reverse challenge we need to find the password for `spaceships`. Huge props to the creator of this challenge it was extremely creative and fun to solve.


<!--more-->
{% raw %}

## The binary file



Here is the grid size: 144, 0x244.


## The game of life

To fully appreciate the beauty of this challenge head to [https://conwaylife.com/wiki](https://conwaylife.com/wiki)

The challenge consist of choosing where to place [MiddleWeight SpaceShips](https://conwaylife.com/wiki/Middleweight_spaceship). These spaceships run into a [converter]() and get transformed into a [glider](https://conwaylife.com/wiki/Glider).

Here is a screenshot of the initial state with an empty user input:

![](/assets/ecw/spaceships/conway.png)

We need to prevent the gliders from colliding into our converters by placing MWSSs. However we also lose if we are greedy and place too many spaceships.

## Flag
Running the program with `0xbadce115` we get:

```
./spaceships badce115
Well done, you have successfully neutralized the enemy. Here is your flag: ECW{BADCE115}
```

FLAG: `ECW{BADCE115}`

{% endraw %}

