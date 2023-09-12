---
layout: post
date: 2023-09-12 18:00:00 +0200
title: "Congratulations"
excerpt_separator: <!--more-->
---

In this challenge, we need to have a look at a suspicious `.docm` file.

<!--more-->

## Examination

Opening it with Word, we notice that this file contains macros and Word warns us that it is unsafe.

## The tool

One of the best tools to use when dealing with Office documents is [oledump](https://blog.didierstevens.com/programs/oledump-py/).

We can use it to extract the macro's source code:

```
$ python3 oledump.py ../Congratulations.docm
A: word/vbaProject.bin
 A1:       419 'PROJECT'
 A2:        71 'PROJECTwm'
 A3: M    4527 'VBA/NewMacros'
 A4: m     938 'VBA/ThisDocument'
 A5:      3274 'VBA/_VBA_PROJECT'
 A6:       570 'VBA/dir'
```

We can extract `NewMacros` using the `-v` flag for VBA decompression and `-s 3` to specify that we are selecting the third item (`NewMacros`).

```
$ python3 oledump.py ../Congratulations.docm -v -s 3
```

Here is the result:

```vb
Attribute VB_Name = "NewMacros"
Dim x51 As String
    Dim x49 As String

    x51 = "C:\Program Files\Internet Explorer\iexplore.exe"

    Dim x50 As Integer
    Dim x47 As Double
    For x50 = 1 To 100
        x47 = Sqr(x50) * 2 + 5 / x50
    Next x50

    MsgBox "cYvSGF9cFrrEmfYFW8Yo", vbInformation, "aThg"

    x49 = [char]0x50 + [char]0x43 + [char]0x54 + [char]0x46 + [char]0x7B + [char]0x33 + [char]0x6E + [char]0x34 + [char]0x62 + [char]0x6C + [char]0x33 + [char]0x5F + [char]0x6D + [char]0x34 + [char]0x63 + [char]0x72 + [char]0x30 + [char]0x35 + [char]0x5F + [char]0x70 + [char]0x6C + [char]0x7A + [char]0x5F + [char]0x32 + [char]0x37 + [char]0x33 + [char]0x31 + [char]0x35 + [char]0x36 + [char]0x37 + [char]0x30 + [char]0x7D

    Shell x51 & " " & x49, vbNormalFocus

    Application.Wait Now + TimeValue("00:00:02")

    MsgBox "sgTdrn8Np2Kpfnmr9y57" & x49, vbInformation, "foSds"

    Dim x45(1 To 10) As Integer
    Dim x46 As Integer
    For x50 = 1 To 10
        x46 = Int((100 - 1 + 1) * Rnd + 1)
        x45(x50) = x46
    Next x50

    Dim x52 As Integer
    Dim x53 As Integer
    For x50 = 1 To 9
        For x53 = x50 + 1 To 10
            If x45(x50) > x45(x53) Then
                x52 = x45(x50)
                x45(x50) = x45(x53)
                x45(x53) = x52
            End If
        Next x53
    Next x50

    Dim x54 As String
    For x50 = 1 To 10
        x54 = x54 & x45(x50) & ", "
    Next x50
    MsgBox "phNuYUNwdHHCJdVL4hJd" & Left(x54, Len(x54) - 2), vbInformation, "LOEC"

    Dim x55 As Worksheet
    Set x55 = ThisWorkbook.Sheets.Add(After:=ThisWorkbook.Sheets(ThisWorkbook.Sheets.Count))
    x55.Name = "TtrZ4"
    Dim x56 As ChartObject
    Set x56 = x55.ChartObjects.Add(Left:=10, Top:=10, Width:=300, Height:=200)

    Dim x57 As Range
    Set x57 = x55.Range("A1:B5")
    x57.Value = Application.WorksheetFunction.RandBetween(1, 100)
    x56.Chart.SetSourceData Source:=x57
    x56.Chart.ChartType = xlColumnClustered

    Exit Sub

ErrorHandler:
    MsgBox "hWgjD9NKf7UqXdAq0GBb", vbCritical, "uv9b"
End Sub
```

We can decode the `x49` string by simply running it's value in PowerShell:

```vb
 [char]0x50 + [char]0x43 + [char]0x54 + [char]0x46 + [char]0x7B + [char]0x33 + [char]0x6E + [char]0x34 + [char]0x62 + [char]0x6C + [char]0x33 + [char]0x5F + [char]0x6D + [char]0x34 + [char]0x63 + [char]0x72 + [char]0x30 + [char]0x35 + [char]0x5F + [char]0x70 + [char]0x6C + [char]0x7A + [char]0x5F + [char]0x32 + [char]0x37 + [char]0x33 + [char]0x31 + [char]0x35 + [char]0x36 + [char]0x37 + [char]0x30 + [char]0x7D
```

We find:

`PCTF{3n4bl3_m4cr05_plz_27315670}`

## Flag

`PCTF{3n4bl3_m4cr05_plz_27315670}`
