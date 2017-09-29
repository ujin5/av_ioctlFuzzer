#-*- coding: utf-8 -*-
from pydbg import *
from pydbg.defines import *

import utils
import random
import threading
import os
import shutil
import time
import sys
import DOC_fuzzer
import PE_fuzzer
import COMP_fuzzer
import ETC_fuzzer
import subprocess
import re
import Mut_Rada


class file_fuzzer:
	def __init__(self):
		self.mutate_count		= 100
		self.mutate_list		 = []
		self.selected_list		 = [] # 크래시 트래킹에 사용할 리스트
		self.eip_list			= []	#크래시 중복체크 (EIP 기준)
		self.sample_file			 = None
		self.sample_dir			= "C:\\fuzz\\in\\"
		self.numbering			= None
		self.tmp_dir			 = "C:\\fuzz\\temp\\"
		self.count				 = 0
		self.max				 = 0

	def rename_filename(self):
		for name in os.listdir(self.sample_dir):
			name_r = name.replace("-", "_")
			os.rename(self.sample_dir + name, self.sample_dir + name_r)
		print "[*] Finish to rename."

	def wincmd(self, cmd):
		return subprocess.Popen(cmd,
			shell=True,
			stdin=subprocess.PIPE,
			stdout=subprocess.PIPE,
			stderr=subprocess.PIPE)

	def file_picker_setting(self):
		cmd = "dir " + self.sample_dir
		pipe = self.wincmd(cmd)
		output, errors = pipe.communicate()
		pipe.stdin.close()
		self.max = int(re.findall('\d+', output.split("\n")[-3])[0])

	# 파일 선택
	def file_picker(self):
		file_list = os.listdir(self.sample_dir)
		file_num = self.count % self.max
		tmp_time = int(time.time() * 100) % 100000000
		if not os.path.isdir( self.tmp_dir + str(tmp_time / 10000) ):
			os.system( "mkdir " +self.tmp_dir + str(tmp_time / 10000) )
		self.numbering = str(tmp_time / 10000) + "\\" + str(tmp_time % 10000) + "-" + str(file_num) + "-"
		self.tmp_file =  file_list[file_num]
		self.sample_file = file_list[file_num]
		## shutil.copy(self.sample_file,	self.tmp_file)
		return

	def fuzz(self):
		
		self.file_picker_setting()
		while True:
			self.file_picker()
			self.mutate_file()

	def mutate_file( self ):
		DOC_list = ["hwp", "doc", "ppt", "xls", "pdf", "chm", "rtf"]
		PE_list = ["exe"]
		COMP_list = ["zip", "gz", "7z", "rar", "cab", "arj"]

		#print self.sample_dir
		#print self.tmp_dir + self.numbering
		#print self.sample_file

		print "[*] Selected file : %s" % self.sample_file
		ext = self.sample_file.split(".")[-1]

		if(ext in COMP_list):
			fuzzer = COMP_fuzzer.COMP_FUZZ(self.sample_dir, self.tmp_dir + self.numbering, self.sample_file)
			fuzzer.Mutation()	
		elif(ext in PE_list):
			fuzzer = PE_fuzzer.PE_FUZZ(self.sample_dir, self.tmp_dir + self.numbering, self.sample_file)
			fuzzer.Mutation()
		elif(ext in DOC_list):
			fuzzer = DOC_fuzzer.DOC_FUZZ(self.sample_dir, self.tmp_dir + self.numbering, self.sample_file)
			fuzzer.Mutation()
		else:
			fuzzer = ETC_fuzzer.ETC_FUZZ(self.sample_dir, self.tmp_dir + self.numbering, self.sample_file)
			fuzzer.Mutation()
		print "[*] Fin Fuzz"

		self.count += 1
		return

if __name__ == "__main__":
	os.system( "mkdir C:\\fuzz\\in C:\\fuzz\\temp C:\\fuzz\\temp" )

	print "[*] Start File Fuzzer."
	fuzzer = file_fuzzer()
	fuzzer.rename_filename()
	fuzzer.fuzz()

	print "[*] Finish File Fuzzer."
