from pyZZUF import *
from fuzz_utils import *
from random import *
from Mut_Rada import *
IMAGE_DOS_HEADER = 0x40
IMAGE_FILE_HEADER =  0x4
IMAGE_OPTIONAL_HEADER = IMAGE_FILE_HEADER + 0x14

class PE_FUZZ:

	def __init__(self, seed_dir, out_dir, filename):

		self.PATH = seed_dir + filename
		self.TARGET = out_dir + filename
		self.FILENAME = filename
		self.DATA = None
		self.EP = None
		self.DOS_HEADER = None
		self.PE_HEADER = None
		self.IsPacked()
		print "IS_PACKED : %d"%self.IS_PACKED

	def Mutation(self):

		self.ParsePE()
		if self.IS_PACKED:
			rdata = self.PackMute()
		else:
			rdata = self.NonPackMute()
		f = open(self.TARGET,'w')
		f.write(rdata)

	def PackMute(self):

		rdata = ""
		
		rdata += self.DATA[:self.e_lfanew+0x2+22]

		ep_zzuf3 = radamsa(self.DATA[self.e_lfanew+0x2+22+1:])
		rdata += ep_zzuf3.mutate()
		
		return rdata

	def NonPackMute(self):

		rdata = ""
		
		rdata += self.DATA[:self.e_lfanew-1] # DOS_HEADER ~ STUB_CODE
		
		rdata += self.PE_HEADER[0x0:0x4] # Signature
		
		lfh_zzuf = radamsa(self.PE_HEADER[IMAGE_FILE_HEADER:IMAGE_OPTIONAL_HEADER])
		rdata += lfh_zzuf.mutate() # PE_HEADER 1 
		
		loh_zzuf1 = radamsa(self.PE_HEADER[IMAGE_OPTIONAL_HEADER:IMAGE_OPTIONAL_HEADER+0x10])
		rdata += loh_zzuf1.mutate() # PE_HEADER 2
		
		rdata += struct.pack('<I',self.EP) # EP
		
		loh_zzuf2 = radamsa(self.PE_HEADER[IMAGE_OPTIONAL_HEADER+0x14:])
		rdata += loh_zzuf2.mutate() # PE_HEADER 3 
		
		return rdata
	
	def ParsePE(self):

		with open(self.PATH,'rb') as f:
			data = f.read()
		print len(data)
		self.DOS_HEADER = data[0x0:IMAGE_DOS_HEADER]
		self.e_lfanew = toDWORD(self.DOS_HEADER[0x3C:0x40])
		self.PE_HEADER = data[self.e_lfanew:]
		self.EP = toDWORD(self.PE_HEADER[IMAGE_OPTIONAL_HEADER + 0x10:IMAGE_OPTIONAL_HEADER + 0x14])
		self.DATA = data

	def IsPacked(self):
		if not self.FILENAME.find("packed") == -1:
			self.IS_PACKED = True 
		else:
			self.IS_PACKED = False
