from pyZZUF import *
from random import choice
import shutil
import os


class OLE_FUZZ:

    def __init__(self, seed_dir, out_dir, filename):
        self.SEED_DIR = seed_dir
        self.OUT_DIR = out_dir
        self.FILENAME = filename
    def Mutation(self):

        with open(self.SEED_DIR + self.FILENAME, 'rb') as f:
            ole = f.read()

        ole = ole[8:]
        ole = pyZZUF(ole)
        ole.set_ratio(0.3)
        
        ole_write = ole.mutate().tostring()
        try:
            with open(self.OUT_DIR + self.FILENAME, 'wb') as f:
                f.write(ole_write)
            return True
        except IOError as error:
            print error
            return False
