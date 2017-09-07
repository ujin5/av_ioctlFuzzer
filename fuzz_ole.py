"""
OLE Fuzzer 
"""
import OleFileIO_PL
import os
import shutil
from random import uniform, sample, choice
import random
from pyZZUF import *

def pick():
    pick_file = choice(os.listdir("seed_dir"))
    try:
        shutil.copy(os.getcwd()+"\\seed_dir\\"+pick_file, "out_dir")
    except:
        emptyTemp()
    finally:
        shutil.copy(os.getcwd()+"\\seed_dir\\"+pick_file, "out_dir")
    return pick_file

class OLE_FUZZ:

    def __init__(self, target_file):
        self.TARGET = target_file 

    def mutate(self):

        self.TARGET = os.getcwd()+"\\out_dir\\"+self.TARGET

        with open(self.TARGET, 'rb') as f:
            ole = f.read()

        ole = ole[9:]
        print ole
        ole = pyZZUF(ole)
        ole_write = ole.mutate()
        try:
            with open(self.TARGET, 'wb') as f:
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
    ole = OLE_FUZZ(target_file)
    if OleFileIO_PL.isOleFile(target_file):
        ole.mutate()
        print "success"
    else:
        continue
