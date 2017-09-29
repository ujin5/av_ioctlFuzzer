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
		self.selected_list	   = [] # 크래시 트래킹에 사용할 리스트
		self.eip_list			= []	#크래시 중복체크 (EIP 기준)
		self.orig_file		   = None
		self.sample_dir		  = "C:\\fuzz\\in"
		self.tmp_file			= None
		self.tmp_dir			 = "C:\\fuzz\\temp"
		self.count			   = 0
		self.max			   = 0


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
		sel_file = str(time.time()).replace(".", "") + "_" + str(file_num) + "_" + file_list[file_num]
		self.tmp_file = self.tmp_dir + "\\" + sel_file
		self.orig_file = self.sample_dir + "\\" + file_list[file_num]
		## shutil.copy(self.orig_file,  self.tmp_file)
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

		print "[*] Selected file : %s" % self.orig_file
		ext = self.orig_file.split(".")[-1]
		
		if(ext in COMP_list):
		  #print self.sample_dir
		  #print self.tmp_dir+ "\\" + self.tmp_file.split("\\")[-1].split("-")[0]
		  #print self.tmp_file
		  fuzzer = COMP_fuzzer.COMP_FUZZ(self.sample_dir + "\\", self.tmp_dir+ "\\" + self.tmp_file.split("\\")[-1].split("-")[0] + "-" + self.tmp_file.split("\\")[-1].split("-")[1] + "-" , self.tmp_file.split("-")[-1])
		  fuzzer.Mutation()  
		elif(ext in PE_list):
		  #print self.sample_dir
		  #print self.tmp_dir
		  #print self.orig_filee
		  #print self.tmp_file
		  fuzzer = PE_fuzzer.PE_FUZZ(self.sample_dir + "\\", self.tmp_dir+ "\\" + self.tmp_file.split("\\")[-1].split("-")[0] + "-" + self.tmp_file.split("\\")[-1].split("-")[1] + "-", self.tmp_file.split("-")[-1])
		  fuzzer.Mutation()
		elif(ext in DOC_list):
		  #print self.sample_dir
		  #print self.tmp_dir
		  #print self.orig_file
		  fuzzer = DOC_fuzzer.DOC_FUZZ(self.sample_dir + "\\", self.tmp_dir+ "\\" + self.tmp_file.split("\\")[-1].split("-")[0] + "-" + self.tmp_file.split("\\")[-1].split("-")[1] + "-", self.tmp_file.split("-")[-1])
		  fuzzer.Mutation()
		else:
		  fuzzer = ETC_fuzzer.ETC_FUZZ(self.sample_dir + "\\", self.tmp_dir+ "\\" + self.tmp_file.split("\\")[-1].split("-")[0] + "-" + self.tmp_file.split("\\")[-1].split("-")[1] + "-" , self.tmp_file.split("-")[-1])
		  fuzzer.Mutation()
		print "[*] Fin Fuzz"
		return

if __name__ == "__main__":
	os.system( "mkdir C:\\fuzz\\in C:\\fuzz\\temp C:\\fuzz\\temp" )

	print "[*] Start File Fuzzer."
	fuzzer = file_fuzzer()
	fuzzer.fuzz()

	print "[*] Finish File Fuzzer."
