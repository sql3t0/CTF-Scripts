#!/bin/env python
import argparse

#Frobnicate a string
def frobnicate(s):
    y = ''
    for x in s:
        y += chr(ord(x) ^ 42)
    return y

#Rotate by 0x80000 (UTF-16 rot)
def rot524288(s):
    y = ''
    for x in s:
        y += chr(ord(x) ^ 0x80000)
    return y

#Rotate by 0x8000 (UTF-8 rot)
def rot32768(s):
    y = ''
    for x in s:
            y += chr(ord(x) ^ 0x8000)
    return y

#Rotate by 47 (ASCII rot)
def rot47(s):
    x = []
    for i in range(len(s)):
        j = ord(s[i])
        if j >= 33 and j <= 126:
            x.append(chr(33 + ((j + 14) % 94)))
        else:
            x.append(s[i])
    return ''.join(x)

#Rotate by 13 (a-z  classic rot)
def rot13(s):
    for char in s:
        d = {}
        for c in (65, 97):
            for i in range(26):
                d[chr(i+c)] = chr((i+13) % 26 + c)
    return "".join([d.get(c, c) for c in s])

#Get arguments
parser = argparse.ArgumentParser()
parser.add_argument('-f', '--frob', required=False)
parser.add_argument('-t', '--rot13', required=False)
parser.add_argument('-s', '--rot47', required=False)
parser.add_argument('-e', '--rot8000', required=False)
parser.add_argument('-y', '--rot80000', required=False)
parser.add_argument('-a', '--all', required=False)
args = parser.parse_args()

if (args.frob):
    try:
        print(frobnicate(args.frob))
    except:
        print("Cannot frobnicate string")

if (args.rot13):
    try:
        print(rot13(args.rot13))
    except:
        print("Cannot rot13 string")

if (args.rot47):
    try:
        print(rot47(args.rot47))
    except:
        print("Cannot rot47 string")

if (args.rot8000):
    try:
        print(rot32768(args.rot8000))
    except:
        print("Cannot rot UTF-8 (rot0x8000 / rot32768) string")

if (args.rot80000):
    try:
        print(rot524288(args.rot80000))
    except:
        print("Cannot rot UTF-16 (rot0x80000 / rot524288)  string")

if (args.all):
    try:
        print("Rot13: ")
        print("=======")
        print(rot13(args.all) + "\n")
    except:
        print("Cannot rot13 string" + "\n")

    try:
        print("Rot47: ")
        print("=======")
        print(rot47(args.all) + "\n")
    except:
        print("Cannot rot47 string" + "\n")

    try:
        print("Rot UTF-8 / 0x800: ")
        print("==================")
        print(rot32768(args.all) + "\n")
    except:
        print("Cannot rot UTF-8 string" + "\n")

    try:
        print("Rot UTF-16 / 0x80000: ")
        print("=====================")
        print(rot524288(args.all) + "\n")
    except:
        print("Cannot rot UTF-16 string" + "\n")

    try:
        print("Frobnicate: ")
        print("===========")
        print(frobnicate(args.all) + "\n")
    except:
        print("Cannot frobnicate string" + "\n")