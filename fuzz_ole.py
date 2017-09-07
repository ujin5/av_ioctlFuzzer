"""
OLE Fuzzer 
"""

import os
import shutil
from random import uniform, sample, choice
import random

def pick():
    pick_file = choice(os.listdir("seed_dir"))
    try:
        shutil.copy(os.getcwd()+"\\seed_dir\\"+pick_file, "out_dir")
    except:
        emptyTemp()
    finally:
        shutil.copy(os.getcwd()+"\\seed_dir\\"+pick_file, "out_dir")

    return pick_file

def mutate(target_file):

    target_file = os.getcwd()+"\\out_dir\\"+target_file
    mutate_position = []

    fuzz_offset = []
    fuzz_byte = xrange(256)

    with open(target_file, 'rb') as f:
        ole = f.read()

    ole_write = bytearray(ole)
    ole_length = len(ole)

    mutate_position = [random.randrange(16, ole_length/(random.randrange(1,10))), random.randrange(16, ole_length/(random.randrange(1,10)))]

    fuzz_offset += sample(xrange(mutate_position[0],mutate_position[0]+mutate_position[1]), int(mutate_position[1]*uniform(0.001, 0.03)))

    for index in fuzz_offset:
        if index >= ole_length : continue
        ole_write[index] = choice(fuzz_byte)

    try:
        with open(target_file, 'wb') as f:
            f.write(ole_write)
        return True
    except IOError as error:
        print error
        return False

def emptyTemp():
    while len(os.listdir("out_dir")) != 0 :
        for x in os.listdir("out_dir"):
            try:
                os.remove(r"out_dir\%s" % x)
            except:
                pass

while True:
    target_file = pick()
    mutate(target_file)
