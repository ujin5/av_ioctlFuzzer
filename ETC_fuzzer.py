from pyZZUF import *
from fuzz_utils import *
from random import *
from Mut_Rada import *


class ETC_FUZZ:

    def __init__(self, seed_dir, out_dir, filename):
    
        self.SEED_DIR = seed_dir
        self.OUT_DIR = out_dir  
        self.FILENAME = filename
        self.INPUT = ""
        self.new_data = ""
        f = open(self.SEED_DIR + self.FILENAME, "rb")
        self.INPUT = f.read()


    def Mutation(self):
    	self.etc_fuzz()


	def etc_fuzz(self):
		rdata = ""
		rdata += radamsa(self.INPUT).mutate()

        return rdata
