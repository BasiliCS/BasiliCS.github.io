---
author: Garfield1002
layout: post
date: 2023-10-02 12:00:00 +0200
tags: reverse ecw
title: "Spaceships"
excerpt_separator: <!--more-->
---

In this reverse challenge we need to find the password for `spaceships`. Huge props to the creator of this challenge it was extremely creative and fun to solve.


<!--more-->
{% raw %}

## The binary file

The main function takes a base16 number as an input and then verifies it:

![](/assets/ecw/spaceships/main.png)

Here's a quick look at the verification function:

![](/assets/ecw/spaceships/simulate.png)

The verification routine has 3 separate parts:

- It initializes patterns
- It simulates 0x12c generations of the game of life and makes sure nothing happens in the last one (no cell is born or dies)
- It verifies other patterns

## How do we understand we are simulating the game of life ?

Here's a closer look at the `simulate_life` function:

![](/assets/ecw/spaceships/life.png)

The verifications with `live_cells == 3` setting something to one and `2 > live_cells | 3 < live_cells` setting the same thing to zero tipped me off quite fast that this was the game of life.

All we have to do now is extract the initial grid and run the simulation in python to see what's happening.

Ghidra has a really nice `Copy Special\Python List` feature.

The grid has dimensions: 144, 0x244.

Equipped with that knowledge, let's see whats happening

## The game of life

Here is a screenshot of the initial state with an empty user input:

![](/assets/ecw/spaceships/conway.png)

And here's what happens with an input of `0xffffffff`:

![](/assets/ecw/spaceships/conway2.png)

## Here's the actual challenge

The challenge consist of choosing where to place [MiddleWeight SpaceShips](https://conwaylife.com/wiki/Middleweight_spaceship). These spaceships run into a [135-degree MWSS-to-G](https://conwaylife.com/wiki/135-degree_MWSS-to-G) and get transformed into a [glider](https://conwaylife.com/wiki/Glider).

We need to prevent the gliders from colliding into our converters by placing MWSSs. However we also lose if we are greedy and place too many spaceships.

A 1 in the binary representation of the flag will place a MWSS while a 0 will leave the slot empty.

## Flag
Running the program with `0xbadce115` we get:

```
./spaceships badce115
Well done, you have successfully neutralized the enemy. Here is your flag: ECW{BADCE115}
```

FLAG: `ECW{BADCE115}`

> If you through this challenge you discovered a pation for the game of life, head to [https://conwaylife.com/wiki](https://conwaylife.com/wiki)

{% endraw %}

