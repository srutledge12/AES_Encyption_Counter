#!/usr/bin/env python3

# Homework Number: 5
# Name: Steven Rutledge
# ECN Login: rutleds
# Due Date: 2/20/22

import sys
from BitVector import *
import AES

def x931(v0, dt, totalNum, key_file):
    # print(v0)
    # print(dt)
    # print(totalNum)
    ret = []
    # keyStrip = 
    FILEOUT = open('dt.bits', 'wb')
    dt.write_to_file(FILEOUT)
    FILEOUT.close()
    first = AES.encrypt('dt.bits', key_file)
    
    # print('first')
    # print(first)
    curV = v0
    count = 0
    while (count < totalNum):
        preSec = curV ^ first
        SecFile = open('SF.bits', 'wb')
        preSec.write_to_file(SecFile)
        SecFile.close()
        Rj = AES.encrypt('SF.bits', key_file)
        ret.append(Rj)
        preThird = first ^ Rj
        ThirdFile = open('TF.bits', 'wb')
        preThird.write_to_file(ThirdFile)
        ThirdFile.close()
        curV = AES.encrypt('TF.bits', key_file)
        
        count+=1

    return(ret)

