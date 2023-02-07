#!/usr/bin/env python3

# Homework Number: 4
# Name: Steven Rutledge
# ECN Login: rutleds
# Due Date: 2/10/22


from operator import sub
import sys
from typing import Counter
from xxlimited import new
from BitVector import *

from gen_key_schedule import *
from gen_tables import *


AES_modulus = BitVector(bitstring='100011011')

shiftRow = [[]]

def encrypt(messageFile, keyFile):
    # print(len(pbox_permutation))
    round_keys = get_encryption_key(keyFile)
    round0 = getString(getStateArray(round_keys[0]))
    # print("round0")
    # print(round0)
    # print("-")
    bv = BitVector(filename = messageFile)
    
    # f = open(outFile, "w")
    while (bv.more_to_read):
        bvBlock = bv.read_bits_from_file( 128 )   
        while(bvBlock._getsize() < 128):
            bvBlock += BitVector(bitstring = '0')   
        # print(bvBlock)
        firstState = getString(getStateArray(bvBlock))

        firstState = firstState ^ round0
        # print(firstState)       
        # print(len(firstState))
        #
        subBox = gen_subbytes_table()
        subBox2 = getStateArray2(subBox)
        # print(subBox2)
        final = firstState
        for round in range(1,len(round_keys)):
            postSub = [[0 for x in range(4)] for x in range(4)]
            preSub = getStateArray(final)
            for i in range(4):
                for j in range(4):
                    
                    a = (preSub[j][i][0:4]).int_val()
                    b = (preSub[j][i][4:8]).int_val()
                    # print(a)
                    new = BitVector(intVal = subBox2[a][b])
                    while(len(new) < 8):
                        new.pad_from_left(1)
                    postSub[j][i] = new
            # printMatB(preSub)
            # print(getString(postSub).get_bitvector_in_hex())
            # print(postSub)

            postShift = [[0 for x in range(4)] for x in range(4)]
            for i in range(4):
                postShift[0][i] = postSub[0][i]
                sub = i-3
                if(sub == -1):
                    sub = 3
                if(sub == -2):
                    sub = 2
                if(sub == -3):
                    sub = 1
                postShift[1][i] = postSub[1][sub]
                sub = i-2
                if(sub == -1):
                    sub = 3
                if(sub == -2):
                    sub = 2
                if(sub == -3):
                    sub = 1
                postShift[2][i] = postSub[2][sub]
                sub = i-1
                if(sub == -1):
                    sub = 3
                if(sub == -2):
                    sub = 2
                if(sub == -3):
                    sub = 1
                postShift[3][i] = postSub[3][sub]
            # print(getString(postShift).get_bitvector_in_hex())

            if(round == 14):
                output = getString(postShift) ^ getString(getStateArray(round_keys[round]))
                break

            postMix = [[0 for x in range(4)] for x in range(4)]
            two = BitVector(intVal = 2)
            three = BitVector(intVal = 3)
            # print(two)
            # print(three)
            for j in range(4):
                postMix[0][j] = two.gf_multiply_modular(postShift[0][j], AES_modulus, 8) ^ three.gf_multiply_modular(postShift[1][j], AES_modulus, 8) ^ postShift[2][j] ^ postShift[3][j]
                postMix[1][j] = postShift[0][j] ^ two.gf_multiply_modular(postShift[1][j], AES_modulus, 8) ^ three.gf_multiply_modular(postShift[2][j], AES_modulus, 8) ^ postShift[3][j]
                postMix[2][j] = postShift[0][j] ^ postShift[1][j] ^ two.gf_multiply_modular(postShift[2][j], AES_modulus, 8) ^ three.gf_multiply_modular(postShift[3][j], AES_modulus, 8)
                postMix[3][j] = three.gf_multiply_modular(postShift[0][j], AES_modulus, 8) ^ postShift[1][j] ^ postShift[2][j] ^ two.gf_multiply_modular(postShift[3][j], AES_modulus, 8)
            
            # print(getString(postMix).get_bitvector_in_hex())
            # print(len(subBox))

            
            final = getString(postMix) ^ getString(getStateArray(round_keys[round]))
        # print((output).get_bitvector_in_hex())
        return(output)
        f.write(output.get_bitvector_in_hex())
            # # break
        
    f.close()
                
def decryption(encryptedFile, keyFile, outFile):
    round_keys = get_encryption_key(keyFile)
    roundL = getString(getStateArray(round_keys[-1]))
    invSubBytesTable = genTables()
    invSub = getStateArray2(invSubBytesTable)

    FILEIN = open(encryptedFile)                                                  #(J)
    bv = BitVector( hexstring = FILEIN.read() )
    f = open(outFile, "w")
    mult = 1
    while(mult * 128 - 1 < bv._getsize()):
        roundRev = len(round_keys)-2    
        bitvec = bv[128*(mult-1): 128*mult]
        # print(roundL)
        # print(bitvec)
        firstState = getStateArray(bitvec ^ roundL)
        nextRound = firstState
        while(roundRev >= 0):
            # print(roundRev)
            # Inv shift
            postShift = [[0 for x in range(4)] for x in range(4)]
            for i in range(4):
                postShift[0][i] = nextRound[0][i]
                sub = i-1
                if(sub == -1):
                    sub = 3
                postShift[1][i] = nextRound[1][sub]
                sub = i-2
                if(sub == -1):
                    sub = 3
                if(sub == -2):
                    sub = 2
                postShift[2][i] = nextRound[2][sub]
                sub = i-3
                if(sub == -1):
                    sub = 3
                if(sub == -2):
                    sub = 2
                if(sub == -3):
                    sub = 1
                postShift[3][i] = nextRound[3][sub]
            # Inv sub
            postSub = [[0 for x in range(4)] for x in range(4)]
            preSub = postShift
            for i in range(4):
                for j in range(4):
                    
                    a = (preSub[j][i][0:4]).int_val()
                    b = (preSub[j][i][4:8]).int_val()
                    # print(a)
                    new = BitVector(intVal = invSub[a][b])
                    while(len(new) < 8):
                        new.pad_from_left(1)
                    postSub[j][i] = new
            # Add round key
            preMix1 = getString(postSub) ^ round_keys[roundRev]
            # Inv mix
            if(roundRev == 0):
                output = preMix1
                break
            preMix = getStateArray(preMix1)
            postMix = [[0 for x in range(4)] for x in range(4)]
            E = BitVector(intVal = 14)
            B = BitVector(intVal = 11)
            D = BitVector(intVal = 13)
            nine = BitVector(intVal = 9)
            # print(two)
            # print(three)
            
            for j in range(4):
                postMix[0][j] = E.gf_multiply_modular(preMix[0][j], AES_modulus, 8) ^ B.gf_multiply_modular(preMix[1][j], AES_modulus, 8) ^ D.gf_multiply_modular(preMix[2][j], AES_modulus, 8) ^ nine.gf_multiply_modular(preMix[3][j], AES_modulus, 8)
                postMix[1][j] = nine.gf_multiply_modular(preMix[0][j], AES_modulus, 8) ^ E.gf_multiply_modular(preMix[1][j], AES_modulus, 8) ^ B.gf_multiply_modular(preMix[2][j], AES_modulus, 8) ^ D.gf_multiply_modular(preMix[3][j], AES_modulus, 8)
                postMix[2][j] = D.gf_multiply_modular(preMix[0][j], AES_modulus, 8) ^ nine.gf_multiply_modular(preMix[1][j], AES_modulus, 8) ^ E.gf_multiply_modular(preMix[2][j], AES_modulus, 8) ^ B.gf_multiply_modular(preMix[3][j], AES_modulus, 8)
                postMix[3][j] = B.gf_multiply_modular(preMix[0][j], AES_modulus, 8) ^ D.gf_multiply_modular(preMix[1][j], AES_modulus, 8) ^ nine.gf_multiply_modular(preMix[2][j], AES_modulus, 8) ^ E.gf_multiply_modular(preMix[3][j], AES_modulus, 8)

            roundRev -= 1
            nextRound = postMix
        # print(output.get_bitvector_in_ascii())
        # break
        mult+=1 
        f.write(output.get_bitvector_in_ascii().rstrip('\0'))
    f.close()
    
def printMatB(input):
    for i in range(4):
        for j in range(4):
            print(input[j][i])
            
def printMatH(input):
    for i in range(4):
        for j in range(4):
            print(input[j][i].get_bitvector_in_hex())

def printString(input):
    out = ''
    for i in range(4):
        for j in range(4):
            out += input[j][i].get_bitvector_in_hex()
    print(out)

def getString(input):
    out = ''
    for i in range(4):
        for j in range(4):
            out += input[j][i].get_bitvector_in_hex()
    return(BitVector(hexstring = out))


def get_encryption_key(keyFile):
    key = ""
    FILEIN = open(keyFile)
    
    key = BitVector(textstring = FILEIN.read())
    temp = key.get_bitvector_in_ascii().rstrip()
    new = BitVector(textstring = temp)
    # print(len(new))
    roundKeys = genKeys(len(new), new)
    # print(roundKeys)
    FILEIN.close
    return roundKeys

def extract_round_key(encryption_key):
    round_keys = []
    key = encryption_key.deep_copy()
    for round_count in range(16):
        [LKey, RKey] = key.divide_into_two()    
        shift = shifts_for_round_key_gen[round_count]
        LKey << shift
        RKey << shift
        key = LKey + RKey
        round_key = key.permute(key_permutation_2)
        round_keys.append(round_key)
    return round_keys

def substitute( expanded_half_block ):
    '''
    This method implements the step "Substitution with 8 S-boxes" step you see inside
    Feistel Function dotted box in Figure 4 of Lecture 3 notes.
    '''
    output = BitVector (size = 32)
    segments = [expanded_half_block[x*6:x*6+6] for x in range(8)]
    for sindex in range(len(segments)):
        row = 2*segments[sindex][0] + segments[sindex][-1]
        column = int(segments[sindex][1:-1])
        output[sindex*4:sindex*4+4] = BitVector(intVal = s_boxes[sindex][row][column], size = 4)
    return output     

def getStateArray(input):
    statearray = [[0 for x in range(4)] for x in range(4)]
    # print(statearray)
    for i in range(4):
        for j in range(4):
            statearray[j][i] = input[32*i + 8*j:32*i + 8*(j+1)]
    # print(statearray)
    # print(len(statearray) * len(statearray[0]))
    return(statearray)

def getStateArray2(input):
    statearray = [[0 for x in range(16)] for x in range(16)]
    Counter = 0
    for i in range(16):
        for j in range(16):
                statearray[i][j] = input[Counter]
                Counter+=1
    # print(statearray)
    # print(len(statearray) * len(statearray[0]))
    return(statearray)



if __name__ == "__main__":
    args = sys.argv[1:]
    print(args)
    if(args[0]) == '-e':
        encrypt(args[1], args[2], args[3])
    
    elif(args[0] == '-d'):
        decryption(args[1], args[2], args[3])
