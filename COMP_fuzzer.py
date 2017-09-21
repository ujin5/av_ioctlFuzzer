from pyZZUF import *
import os
import ZIP_fuzz 
import zlib
from Mut_Rada import *
# import fuzz_utils


class COMP_FUZZ:

    def __init__(self, seed_dir, out_dir, filename):
    
        self.SEED_DIR = seed_dir
        self.OUT_DIR = out_dir  
        self.FILENAME = filename
        self.INPUT = ""
        self.new_data = ""
        f = open(self.SEED_DIR + self.FILENAME, "rb")
        self.INPUT = f.read()

    def Mutation(self):

        ext = self.FILENAME.split(".")[-1]
    
        if(ext == "zip"):
            self.new_data = self.zip_fuzz()
            
        elif(ext == "gz"):
            self.new_data = self.gzip_fuzz()
            
        elif(ext == "7z"):
            self.new_data = self.sevenzip_fuzz()
            
        elif(ext == "rar"):
            self.new_data = self.rar_fuzz()

        else:
            self.new_data = None

        if(self.new_data != None):       
            f = open(self.OUT_DIR + self.FILENAME, "wb")
            f.write(self.new_data)
      
    def zip_FIRST_HEADER(self, data):

        SIGN = data[:4]
        
        rdata = ""
        rdata += SIGN
        rdata += radamsa(data[4:]).mutate()    #frversion & flags
    
        return rdata

    def zip_SECOND_HEADER(self,data):

        SIGN = data[:4]

        rdata = ""
        rdata += SIGN
        rdata += radamsa(data[4:]).mutate()
        
        return rdata

    def zip_THIRD_HEADER(self, data):

        SIGN = data[:4]

        rdata = ""
        rdata += SIGN
        rdata += data[4:6]
        rdata += radamsa(data[6:]).mutate()
        
        return rdata

    def zip_fuzz(self):
        
        length = len(self.INPUT)
        
        FIRST_SIGN = chr(0x50) + chr(0x4b) + chr(0x03) + chr(0x04)
        SECOND_SIGN = chr(0x50) + chr(0x4b) + chr(0x01) + chr(0x02)
        THIRD_SIGN = chr(0x50) + chr(0x4b) + chr(0x05) + chr(0x06)
        
        FIRST_SECTION = self.INPUT[:self.INPUT.find(SECOND_SIGN)]
        SECOND_SECTION = self.INPUT[self.INPUT.find(SECOND_SIGN) : self.INPUT.find(THIRD_SIGN)]
        THIRD_SECTION = self.INPUT[self.INPUT.find(THIRD_SIGN):]

        fileCNT = FIRST_SECTION.count(FIRST_SIGN)

        rdata = "" 

        for i in range(fileCNT):
            rdata += self.zip_FIRST_HEADER(FIRST_SIGN + FIRST_SECTION.split(FIRST_SIGN)[i+1])

        for j in range(fileCNT):
            rdata += self.zip_SECOND_HEADER(SECOND_SIGN + SECOND_SECTION.split(SECOND_SIGN)[j+1])

        rdata += self.zip_THIRD_HEADER(THIRD_SECTION)

        return rdata

    def gzip_fuzz(self):

        length = len(self.INPUT)
        
        SIGN = self.INPUT[:2]
        
        rdata = ""
        rdata += SIGN
        rdata += radamsa(self.INPUT[2:]).mutate()
        
        return rdata    

    def sevenzip_fuzz(self):   
    
        SIGN = self.INPUT[:6]

        zzbuf = radamsa(self.INPUT[6:])
    
        rdata = ""
        rdata += SIGN
        rdata += zzbuf.mutate()

        return rdata


    def rar_fuzz(self):
    
        FIRST_HEADER = self.INPUT[:0x7]
        
        rdata = ""
        rdata += FIRST_HEADER
        rdata += radamsa(self.INPUT[7:]).mutate()
        
        return rdata
