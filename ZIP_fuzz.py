from struct import *
from optparse import OptionParser
import random
import sys

class Crand:
    
    @staticmethod
    def randomBytes(n):
        return bytearray(random.getrandbits(8) for i in range(n))
    
    @staticmethod
    def random_localFileHeader(val, length):
        random_index = []
        for i in range(0,length):
            index = random.randrange(0,len(val))
            if index not in random_index:
                random_index.append(index)    
        return random_index

    @staticmethod
    def getRandNumber(structLen):
        return random.randrange(0,len(structLen))

    @staticmethod
    def getSeed():
        return random.randrange(0, 9223372036854775807)
    
class Cpack:

    def __init__(self, valDict, valLoc):
        self.valDict = valDict
        self.valLoc = valLoc
        
    def packHeader4byte(self, index):
        global content
        if index in self.valLoc:
            f, s, t, q = Crand().randomBytes(4)
            content += pack('4B', f, s, t, q)
        else:
            content += pack('I', self.valDict[index])
    
    def packHeaderHbyte(self, index):
        global content
        if index in self.valLoc:
            f, s = Crand().randomBytes(2)
            content += pack('2B', f, s)
        else:
            content += pack('H', self.valDict[index])
                
    def packHeader2byte(self, index):
        global content
        if index in self.valLoc:
            f, s = Crand().randomBytes(2)
            content += pack('2B', f, s)
        else:
            content += pack('2B', *self.valDict[index])
    
    def packHeadernbyte(self, index, len):
        global content
        if index in self.valLoc:
            lst = []
            len = random.randrange(0, 255)
            lst = Crand().randomBytes(len)
            sub = tuple(lst)
            content += pack(str(len) + 'B', *sub)
        else:
            content += pack(str(len) + 'B', *self.valDict[index])

class ClocalHeader:

    def __init__(self, dictLocalFileHeader, locFileHeadList):
        self.dictLocalFileHeader = dictLocalFileHeader
        self.locFileHeadList = locFileHeadList
        
    def fuzzLocalHeader(self, signature):
        global content
            
        content += pack('4B', *signature)
        
        packElem = Cpack(self.dictLocalFileHeader, self.locFileHeadList)
        
        [packElem.packHeader2byte(i) for i in range(0, 4)]
        [packElem.packHeader4byte(i) for i in range(5, 7)]
        [packElem.packHeaderHbyte(i) for i in range(8, 9)]
        
        packElem.packHeadernbyte(10, len(self.dictLocalFileHeader[10]))
        packElem.packHeadernbyte(11, len(self.dictLocalFileHeader[11]))
        packElem.packHeadernbyte(12, len(self.dictLocalFileHeader[12]))

class CcentralDir:
  
    def __init__(self, dictCentralDir, centrDirList):
        self.dictCentralDir = dictCentralDir
        self.centrDirList = centrDirList
        
    def fuzzCentralDir(self, signature):
        global content
            
        content += pack('4B', *signature)
    
        packElem = Cpack(self.dictCentralDir, self.centrDirList)
        
        [packElem.packHeader2byte(i) for i in range(0, 5)]
        [packElem.packHeader4byte(i) for i in range(6, 8)]
        [packElem.packHeaderHbyte(i) for i in range(9, 11)]
        [packElem.packHeader2byte(i) for i in range(12, 13)]
        [packElem.packHeader4byte(i) for i in range(14, 15)]
        
        packElem.packHeadernbyte(16, len(self.dictCentralDir[16]))
        packElem.packHeadernbyte(17, len(self.dictCentralDir[17]))
        packElem.packHeadernbyte(18, len(self.dictCentralDir[18]))

class CendOfCentralDir:

    def __init__(self, dictEndOfCentralDir, endOfcentrDirList):
        self.dictEndOfCentralDir = dictEndOfCentralDir
        self.endOfcentrDirList = endOfcentrDirList
        
    def fuzzendOfCentralDir(self, endOfCentralDirSig):
        global content
            
        content += pack('4B', *endOfCentralDirSig)
        
        packElem = Cpack(self.dictEndOfCentralDir, self.endOfcentrDirList)
        
        [packElem.packHeader2byte(i) for i in range(0, 3)]
        [packElem.packHeader4byte(i) for i in range(4, 5)]
        
        packElem.packHeaderHbyte(6)
        packElem.packHeadernbyte(7, len(self.dictEndOfCentralDir[7]))

class CfileManag:
    
    def setInputFilename(self, fileName):
        self.fileName = fileName
        
    def getInputFileName(self):
        return self.fileName
    
    def createFile(self, fileNameOut):
        with open(fileNameOut, mode='wb') as file:
            print content
            writeContent = file.write(content)

def main(seed_dir, out_dir, Filename):
    
    fileElem = CfileManag()
    fileElem.setInputFilename(Filename)
    
    seed = Crand().getSeed()
        
    fileName = fileElem.getInputFileName()
    
    random.seed(seed)
    
    with open(seed_dir + fileName, mode='rb') as file:
        fileContent = file.read()
        
        # local header
        signature = unpack('4B', fileContent[0:4])
        version = unpack('2B', fileContent[4:6])
        flags = unpack('2B', fileContent[6:8])
        compression = unpack('2B', fileContent[8:10])
        modTime = unpack('2B', fileContent[10:12])
        modDate = unpack('2B', fileContent[12:14])
        crc32 = unpack('I', fileContent[14:18])[0]
        compressSize = unpack('I', fileContent[18:22])[0]
        uncompressSize = unpack('I', fileContent[22:26])[0]
        fileNameLen = unpack('H', fileContent[26:28])[0]
        extraFieldLen = unpack('H', fileContent[28:30])[0]
        endFileName = 30 + fileNameLen
        endExtraField = endFileName + extraFieldLen
        fileName = unpack(str(fileNameLen)+'B', fileContent[30:endFileName])
        extraField = unpack(str(extraFieldLen)+'B', fileContent[endFileName:endExtraField])
    
        # file data
        if (compressSize!=0):
            endCompSize = endExtraField + compressSize
            data = unpack(str(compressSize)+'B', fileContent[endExtraField:endCompSize])    
        
        else:
            exit(0)
        # no data descriptor
    
        # Central directory structure
        centralDirectorySig = fileContent.find('\x50\x4b\x01\x02')
        if (centralDirectorySig != -1):
            endCentrDir = centralDirectorySig + 4
            CDsignature = unpack('4B', fileContent[centralDirectorySig:endCentrDir])
            endCDversion = endCentrDir + 2
            CDversion = unpack('2B', fileContent[endCentrDir:endCDversion])
            endCDversionNeed = endCDversion + 2
            CDversionNeed = unpack('2B', fileContent[endCDversion:endCDversionNeed])
            endCDbitFlag = endCDversionNeed + 2
            CDbitFlag = unpack('2B', fileContent[endCDversionNeed:endCDbitFlag])
            endCDcompression = endCDbitFlag + 2
            CDcompression = unpack('2B', fileContent[endCDbitFlag:endCDcompression])
            endCDmodTime = endCDcompression + 2
            CDmodTime = unpack('2B', fileContent[endCDcompression:endCDmodTime])
            endCDmodDate = endCDmodTime + 2
            CDmodDate = unpack('2B', fileContent[endCDmodTime:endCDmodDate])
            endCDcrc32 = endCDmodDate + 4
            CDcrc32 = unpack('I', fileContent[endCDmodDate:endCDcrc32])[0]
            endCDcompressSize = endCDcrc32 + 4
            CDcompressSize = unpack('I', fileContent[endCDcrc32:endCDcompressSize])[0]
            endCDuncompressSize = endCDcompressSize + 4
            CDuncompressSize = unpack('I', fileContent[endCDcompressSize:endCDuncompressSize])[0]
            endCDfileNameLen = endCDuncompressSize + 2
            CDfileNameLen = unpack('H', fileContent[endCDuncompressSize:endCDfileNameLen])[0]
            endCDextraFieldLen = endCDfileNameLen + 2
            CDextraFieldLen = unpack('H', fileContent[endCDfileNameLen:endCDextraFieldLen])[0]
            endCDfileCommLen = endCDextraFieldLen + 2
            CDfileCommLen = unpack('H', fileContent[endCDextraFieldLen:endCDfileCommLen])[0]
            endCDdiskNumStart = endCDfileCommLen + 2
            CDdiskNumStart = unpack('2B', fileContent[endCDfileCommLen:endCDdiskNumStart])
            endCDintFileAttr = endCDdiskNumStart + 2
            CDintFileAttr = unpack('2B', fileContent[endCDdiskNumStart:endCDintFileAttr])
            endCDextFileAttr = endCDintFileAttr + 4
            CDextFileAttr = unpack('I', fileContent[endCDintFileAttr:endCDextFileAttr])[0]
            endCDrelOffset = endCDextFileAttr + 4
            CDrelOffset = unpack('I', fileContent[endCDextFileAttr:endCDrelOffset])[0]
            endCDFileName = endCDrelOffset + CDfileNameLen
            CDFileName = unpack(str(CDfileNameLen) + 'B', fileContent[endCDrelOffset:endCDFileName])
            endCDExtraField = endCDFileName + CDextraFieldLen
            CDExtraField = unpack(str(CDextraFieldLen) + 'B', fileContent[endCDFileName:endCDExtraField])
            endCDFileComment = endCDExtraField + CDfileCommLen
            CDFileComment = unpack(str(CDfileCommLen) + 'B', fileContent[endCDExtraField:endCDFileComment])
        
        # end of central directory structure
        endOfCentralDirSig = fileContent.find('\x50\x4b\x05\x06')
        
        if (endOfCentralDirSig != -1):
            endECD =  endOfCentralDirSig + 4
            EDCsignature = unpack('4B', fileContent[endOfCentralDirSig:endECD]) 
            endECDdiskNumber = endECD + 2
            ECDdiskNumber = unpack('2B', fileContent[endECD:endECDdiskNumber])
            endECDcentDirStartDisk = endECDdiskNumber + 2
            ECDcentDirStartDisk = unpack('2B', fileContent[endECDdiskNumber:endECDcentDirStartDisk])
            endECDcentDirStartDiskOff = endECDcentDirStartDisk + 2
            ECDcentDirStartDiskOff = unpack('2B', fileContent[endECDcentDirStartDisk:endECDcentDirStartDiskOff])
            endECDnumEntry = endECDcentDirStartDiskOff + 2
            ECDnumEntry = unpack('2B', fileContent[endECDcentDirStartDiskOff:endECDnumEntry])
            endECDcentrDirSize = endECDnumEntry + 4
            ECDcentrDirSize = unpack('I', fileContent[endECDnumEntry:endECDcentrDirSize])[0]
            endECDcentrDirOff = endECDcentrDirSize + 4
            ECDcentrDirOff = unpack('I', fileContent[endECDcentrDirSize:endECDcentrDirOff])[0]
            endECDcommLen = endECDcentrDirOff + 2
            ECDcommLen = unpack('H', fileContent[endECDcentrDirOff:endECDcommLen])[0]
            endECDzipComment = endECDcommLen + ECDcommLen
            ECDzipComment = unpack(str(ECDcommLen) + 'B', fileContent[endECDcommLen:endECDzipComment])
            
            
    localFileHeader = [version, flags, compression, modTime, modDate, crc32, compressSize, uncompressSize, fileNameLen, extraFieldLen, fileName, extraField, data]
    centralDirectoryStruct = [CDversion, CDversionNeed, CDbitFlag, CDcompression, CDmodTime, CDmodDate, CDcrc32, CDcompressSize, CDuncompressSize, CDfileNameLen, CDextraFieldLen, CDfileCommLen, CDdiskNumStart, CDintFileAttr, CDextFileAttr, CDrelOffset, CDFileName, CDExtraField, CDFileComment]
    endOfCentralDirectoyStruct = [ECDdiskNumber, ECDcentDirStartDisk, ECDcentDirStartDiskOff, ECDnumEntry, ECDcentrDirSize, ECDcentrDirOff, ECDcommLen, ECDzipComment]
    
    locFileHeadList = Crand().random_localFileHeader(localFileHeader, Crand().getRandNumber(localFileHeader))
    centrDirList = Crand().random_localFileHeader(centralDirectoryStruct, Crand().getRandNumber(centralDirectoryStruct))
    endOfcentrDirList = Crand().random_localFileHeader(endOfCentralDirectoyStruct, Crand().getRandNumber(endOfCentralDirectoyStruct))
    
    dictLocalFileHeader = { 0 : version,
                        1 : flags,
                        2 : compression,
                        3 : modTime,
                        4 : modDate,
                        5 : crc32,
                        6 : compressSize,
                        7 : uncompressSize,
                        8 : fileNameLen,
                        9 : extraFieldLen,
                        10 : fileName,
                        11 : extraField,
                        12 : data
                        }
    
    dictCentralDir  = { 0 : CDversion,
                        1 : CDversionNeed,
                        2 : CDbitFlag,
                        3 : CDcompression,
                        4 : CDmodTime,
                        5 : CDmodDate,
                        6 : CDcrc32,
                        7 : CDcompressSize,
                        8 : CDuncompressSize,
                        9 : CDfileNameLen,
                        10 : CDextraFieldLen,
                        11 : CDfileCommLen,
                        12 : CDdiskNumStart,
                        13 : CDintFileAttr,
                        14 : CDextFileAttr,
                        15 : CDrelOffset,
                        16 : CDFileName,
                        17 : CDExtraField,
                        18 : CDFileComment
                        }
    
    dictEndOfCentralDir = { 0 : ECDdiskNumber,
                        1 : ECDcentDirStartDisk,
                        2 : ECDcentDirStartDiskOff,
                        3 : ECDnumEntry,
                        4 : ECDcentrDirSize,
                        5 : ECDcentrDirOff,
                        6 : ECDcommLen,
                        7 : ECDzipComment
                        }
                        
    global content
    content = ''
        
    callLocHead = ClocalHeader(dictLocalFileHeader, locFileHeadList)
    callLocHead.fuzzLocalHeader(signature)
    
    callCentrDir = CcentralDir(dictCentralDir, centrDirList)
    callCentrDir.fuzzCentralDir(CDsignature)
    
    callEndOfCentrDir = CendOfCentralDir(dictEndOfCentralDir, endOfcentrDirList)
    callEndOfCentrDir.fuzzendOfCentralDir(EDCsignature)
    
    fileElem.createFile(out_dir + Filename)

if __name__ == "__main__":
    main()
