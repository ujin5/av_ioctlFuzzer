from pyZZUF import *
import fuzz_utils

IMAGE_DOS_HEADER = 0x0
IMAGE_FILE_HEADER =  0x4
IMAGE_OPTIONAL_HEADER = IMAGE_FILE_HEADER + 0x14

class PE_FUZZ(object):

	def __init__(self, path, target):

		self.PATH = path
		self.TARGET = target
		self.DATA = None
		self.EP = None
		self.DOS_HEADER = None
		self.PE_HEADER = None
		self.IsPacked()
		print "IS_PACKED : %d"%self.IS_PACKED

	def Mutation(self):

		self.ParsePE()
		rdata = self.IS_PACKED ? PackMute() : NonPackMute() 
		f = open(self.TARGET,'w')
		f.write(rdata)

	def PackMute(self):

		rdata = ""
		
		rdata += self.DATA[:self.e_lfanew] # DOS_HEADER ~ STUB_CODE
		
		rdata += self.PE_HEADER[0x0:0x4] # Signature
		
		lfh_zzbuf = pyZZUF(self.PE_HEADER[IMAGE_FILE_HEADER:IMAGE_OPTIONAL_HEADER])
		rdata += lfh_zzuf.mutate().tostring().decode() # PE_HEADER 1 
		
		loh_zzbuf1 = pyZZUF(self.PE_HEADER[IMAGE_OPTIONAL_HEADER:IMAGE_OPTIONAL_HEADER+0x10])
		rdata += loh_zzuf1.mutate().tostring().decode() # PE_HEADER 2
		
		rdata += struct.pack('<I',self.EP) # EP
		
		loh_zzbuf2 = pyZZUF(self.PE_HEADER[IMAGE_OPTIONAL_HEADER+0x14:self.EP])
		rdata += loh_zzuf2.mutate().tostring().decode() # PE_HEADER 3 
		
		rdata += self.PE_HEADER[self.EP:self.EP+0x20] #Save Packer Signature 
		
		ep_zzbuf3 = pyZZUF(self.PE_HEADER[self.EP+0x20:])	
		rdata += ep_zzbuf3.mutate().tostring().decode() 

		return rdata

	def NonPackMute(self):

		rdata = ""
		
		rdata += self.DATA[:self.e_lfanew] # DOS_HEADER ~ STUB_CODE
		
		rdata += self.PE_HEADER[0x0:0x4] # Signature
		
		lfh_zzbuf = pyZZUF(self.PE_HEADER[IMAGE_FILE_HEADER:IMAGE_OPTIONAL_HEADER])
		rdata += lfh_zzuf.mutate().tostring().decode() # PE_HEADER 1 
		
		loh_zzbuf1 = pyZZUF(self.PE_HEADER[IMAGE_OPTIONAL_HEADER:IMAGE_OPTIONAL_HEADER+0x10])
		rdata += loh_zzuf1.mutate().tostring().decode() # PE_HEADER 2
		
		rdata += struct.pack('<I',self.EP) # EP
		
		loh_zzbuf2 = pyZZUF(self.PE_HEADER[IMAGE_OPTIONAL_HEADER+0x14:])
		rdata += loh_zzuf2.mutate().tostring().decode() # PE_HEADER 3 
		
		return rdata
	
	def ParsePE(self):

		with open(self.PATH,'r') as f:
			data = f.read()
		self.DOS_HEADER = data[0x0:IMAGE_DOS_HEADER]
		self.e_lfanew = toDWORD(self.DOS_HEADER[0x3C:0x40])
		self.PE_HEADER = data[self.e_lfanew:]
		self.EP = toDWORD(self.PE_HEADER[IMAGE_OPTIONAL_HEADER + 0x10:IMAGE_OPTIONAL_HEADER + 0x14])
		self.DATA = data
	
	def IsPacked(self):

		self.IS_PACKED = path.find("packed") ? 1 : 0
