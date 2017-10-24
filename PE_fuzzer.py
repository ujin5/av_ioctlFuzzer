from pyZZUF import *
from fuzz_utils import *
from random import *
from Mut_Rada import *

class PE_FUZZ:

	def __init__(self, seed_dir, out_dir, filename):

		self.PATH = seed_dir + filename
		self.TARGET = out_dir + filename
		self.FILENAME = filename
		self.DATA = None
		self.IsPacked()
		print "IS_PACKED : %d"%self.IS_PACKED

	def Mutation(self):

		self.ParsePE()
		rdata = self.DoMute()
		f = open(self.TARGET,'wb')
		f.write(rdata)
	def DoMute(self):
		rdata = self.DATA[ : self.e_lfanew+0x38]
		rdata += radamsa(self.DATA[self.e_lfanew + 0x18 + 0x20 : self.e_lfanew + 0x18 + self.size_of_op_header]).mutate()[:self.size_of_op_header - 0x20]
		rdata += radamsa(self.DATA[len(rdata):]).mutate()
		return rdata
	def ParsePE(self):

		with open(self.PATH,'rb') as f:
			data = f.read()
		print len(data)
		self.e_lfanew = toDWORD(data[0x3C:0x40])
		self.number_of_section = toWORD(data[self.e_lfanew : self.e_lfanew + 2])
		self.size_of_op_header = toWORD(data[self.e_lfanew : self.e_lfanew + 0x14])
		self.DATA = data

	def IsPacked(self):
		if not self.FILENAME.find("packed") == -1:
			self.IS_PACKED = True 
		else:
			self.IS_PACKED = False
