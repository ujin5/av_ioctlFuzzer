from pyZZUF import *
from random import choice
import shutil
import os


class OLE_FUZZ:

    def __init__(self, seed_dir, out_dir, filename):
        self.TARGET = out_dir + filename 

    def Mutation(self):

        with open(self.TARGET, 'rb') as f:
            ole = f.read()

        ole = ole[8:]
        ole = pyZZUF(ole)
        ole.set_ratio(0.3)
        
        ole_write = ole.mutate().tostring()
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

