from pyZZUF import *
import os
import ZIP_fuzz 
import zlib
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

        ext = self.FILENAME.split(".")[1]
    
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
        rdata += pyZZUF(data[4:8]).mutate().tostring()     #frversion & flags
        rdata += data[8:10]
        rdata += pyZZUF(data[10:26]).mutate().tostring()
        rdata += data[26:]        
    
        return rdata

    def zip_SECOND_HEADER(self,data):

        SIGN = data[:4]

        rdata = ""
        rdata += SIGN
        rdata += pyZZUF(data[4:10]).mutate().tostring()
        rdata += data[10:12]
        rdata += pyZZUF(data[12:16]).mutate().tostring()
        rdata += data[16:34]        # decrc, decompressed size, filename length, etc.
        rdata += pyZZUF(data[34:42]).mutate().tostring()
        rdata += data[42:46]
        rdata += pyZZUF(data[46:]).mutate().tostring()

        return rdata

    def zip_THIRD_HEADER(self, data):

        SIGN = data[:4]

        rdata = ""
        rdata += SIGN
        rdata += data[4:6]
        rdata += pyZZUF(data[6:16]).mutate().tostring()
        rdata += data[16:]

        return rdata

    def zip_fuzz(self):
        
        length = len(self.INPUT)
        
        FIRST_SIGN = chr(0x50) + chr(0x4b) + chr(0x03) + chr(0x04)
        SECOND_SIGN = chr(0x50) + chr(0x4b) + chr(0x01) + chr(0x02)
        THIRD_SIGN = chr(0x50) + chr(0x4b) + chr(0x05) + chr(0x06)
        
        FIRST_SECTION = self.INPUT[:self.INPUT.find(SECOND_SIGN)]
        SECOND_SECTION = self.INPUT[self.INPUT.find(SECONDE_SIGN) : self.INPUT.find(THIRD_SIGN)]
        THIRD_SECTION = self.INPUT[self.INPUT.find(THIRD_SIGN):]

        fileCNT = FIRST_SECTION.count(FIRST_SECTION)

        rdata = "" 

        for i in range(fileCNT):
            rdata += zip_FIRST_HEADER(FIRST_SIGN + FIRST_SECTION.split(FIRST_SIGN)[i+1])

        for i in range(fileCNT):
            rdata += zip_SECOND_HEADER(SECOND_SIGN + SECOND_SECTION.split(SECOND_SIGN)[i+1])

        rdata += zip_THIRD_HEADER(THIRD_SECTION)

        return rdata

    def gzip_fuzz(self):
        
        SIGN = self.INPUT[:2]
        CHECKSUM = self.INPUT[length-8:length-4]
        FILESIZE = self.INPUT[length-4:]

        rdata = ""
        rdata += SIGN
        rdata += self.INPUT[2:4]    # compression method & flag
        rdata += pyZZUF(self.INPUT[4:10]).mutate().tostring()
        rdata += self.INPUT[10:length-8]
        rdata += CHECKSUM
        rdata += pyZZUF(FILESIZE[:2]).mutate().tostring()   # upper 2 bytes
        rdata += FILESIZE[2:]

        return rdata    

    def sevenzip_fuzz(self):   # so dirty......
    
        SIGN = self.INPUT[:6]

        zzbuf = pyZZUF(self.INPUT[6:])
    
        rdata = ""
        rdata += SIGN
        rdata += zzbuf.mutate().tostring()

        return rdata


    def rar_fuzz(self):
    
        FIRST_HEADER = self.INPUT[:0x7]
        
        ARC_HEADER = pyZZUF(self.INPUT[0x7:0x9]).mutate().tostring()
        ARC_HEADER += self.INPUT[0x9:0xE]
        ARC_HEADER += pyZZUF(self.INPUT[0xE:0x14]).mutate().tostring()

        LAST_HEADER = self.INPUT[-7:]
        
        rdata = ""
        rdata += FIRST_HEADER
        rdata += ARC_HEADER
        rdata += self.INPUT[0x14:-7]
        rdata += LAST_HEADER
        
        return rdata
