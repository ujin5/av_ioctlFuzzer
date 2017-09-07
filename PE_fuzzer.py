from pyZZUF import *
import fuzz_utils

IMAGE_DOS_HEADER = 0x0
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
			rdata = PackMute()
		else:
			rdata = NonPackMute()
		f = open(self.TARGET,'w')
		f.write(rdata)

	def PackMute(self):

		rdata = ""
		
		rdata += self.DATA[:self.e_lfanew] # DOS_HEADER ~ STUB_CODE
		
		rdata += self.PE_HEADER[0x0:0x4] # Signature
		
		lfh_zzuf = pyZZUF(self.PE_HEADER[IMAGE_FILE_HEADER:IMAGE_OPTIONAL_HEADER])
		lfh_zzuf.set_ratio(0.3)
		rdata += lfh_zzuf.mutate().tostring().decode() # PE_HEADER 1 
		
		loh_zzuf1 = pyZZUF(self.PE_HEADER[IMAGE_OPTIONAL_HEADER:IMAGE_OPTIONAL_HEADER+0x10])
		loh_zzuf1.set_ratio(0.3)
		rdata += loh_zzuf1.mutate().tostring().decode() # PE_HEADER 2
		
		rdata += struct.pack('<I',self.EP) # EP
		
		loh_zzuf2 = pyZZUF(self.PE_HEADER[IMAGE_OPTIONAL_HEADER+0x14:self.EP])
		loh_zzuf2.set_ratio(0.3)
		rdata += loh_zzuf2.mutate().tostring().decode() # PE_HEADER 3 
		
		rdata += self.PE_HEADER[self.EP:self.EP+0x20] #Save Packer Signature 
		
		ep_zzuf3 = pyZZUF(self.PE_HEADER[self.EP+0x20:])	
		ep_zzuf3.set_ratio(0.3)
		rdata += ep_zzuf3.mutate().tostring().decode() 

		return rdata

	def NonPackMute(self):

		rdata = ""
		
		rdata += self.DATA[:self.e_lfanew] # DOS_HEADER ~ STUB_CODE
		
		rdata += self.PE_HEADER[0x0:0x4] # Signature
		
		lfh_zzuf = pyZZUF(self.PE_HEADER[IMAGE_FILE_HEADER:IMAGE_OPTIONAL_HEADER])
		lfh_zzuf.set_ratio(0.3)
		rdata += lfh_zzuf.mutate().tostring().decode() # PE_HEADER 1 
		
		loh_zzuf1 = pyZZUF(self.PE_HEADER[IMAGE_OPTIONAL_HEADER:IMAGE_OPTIONAL_HEADER+0x10])
		loh_zzuf1.set_ratio(0.3)
		rdata += loh_zzuf1.mutate().tostring().decode() # PE_HEADER 2
		
		rdata += struct.pack('<I',self.EP) # EP
		
		loh_zzuf2 = pyZZUF(self.PE_HEADER[IMAGE_OPTIONAL_HEADER+0x14:])
		loh_zzuf2.set_ratio(0.3)
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
		if self.FILENAME.find("packed"):
			self.IS_PACKED = True 
		else:
			self.IS_PACKED = False
