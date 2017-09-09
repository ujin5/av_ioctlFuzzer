# -*- coding: utf-8 -*-
from pydbg import *
from pydbg.defines import *

import utils
import random
import threading
import os
import shutil
import time
import sys
import OLE_fuzzer
import PE_fuzzer
import COMP_fuzzer
import subprocess
import re

class file_fuzzer:
	def __init__(self, exe_path):
		self.mutate_count		= 100
		self.mutate_list		 = []
		self.selected_list	   = [] # 크래시 트래킹에 사용할 리스트
		self.eip_list			= []	#크래시 중복체크 (EIP 기준)
		self.exe_path			= exe_path
		self.ext				 = ".hwp"
		self.orig_file		   = None
		self.sample_dir		  = "C:\\fuzz\\in"
		self.tmp_file			= None
		self.tmp_dir			 = "C:\\fuzz\\temp"
		self.count			   = 0
		self.max			   = 0
		self.crash			   = None
		self.crash_tracking	  = False # 크래시 추적 활성화 체크
		self.crash_count		 = None # 크래시 번호 저장
		self.tracking_count	  = 0 # 트래킹 카운트 저장(무한루프 방지)
		self.check			   = False
		self.pid				 = None
		self.in_accessv_handler  = False
		self.dbg				 = None
		self.running			 = False

		self.running_ads		 = False
		self.pid_ads			 = None
		self.dbg_ads			 = None

	def file_picker_setting(self):
		cmd = "dir " + self.sample_dir
		pipe = subprocess.Popen(cmd,
		    shell=True,
		    stdin=subprocess.PIPE,
			stdout=subprocess.PIPE,
		    stderr=subprocess.PIPE)
		output, errors = pipe.communicate()
		pipe.stdin.close()
		self.max = int(re.findall('\d+', output.split("\n")[-3])[0])
		print self.max


	# 파일 선택
	def file_picker(self):
		file_list = os.listdir(self.sample_dir)
		file_num = self.count % self.max
		sel_file = file_list[file_num]
		self.tmp_file = self.tmp_dir+ sel_file
		# print sel_file
		# print self.tmp_file
		self.orig_file = self.sample_dir + "\\" +sel_file
		## shutil.copy(self.orig_file,  self.tmp_file)
		return

	def fuzz(self):
		
		self.file_picker_setting()

		# 디버거 쓰레드 실행
		pydbg_ads_thread = threading.Thread(target=self.start_ASDsvc_debugger)
		pydbg_ads_thread.setDaemon(0)
		pydbg_ads_thread.start()

		while self.pid_ads == None:
			time.sleep(0.5)

		while 1:

			while self.running :
				time.sleep(1)

			self.running = True

			print "[*] Starting debugger for iteration: %d" % self.count

			# 크래시 추적 활성화 여부 체크
			if self.crash_tracking == False:
				# 먼저 변형을 가할 파일을 선택한다.
				self.file_picker()
				self.mutate_file()
			else: #크래시 추적이 활성화 되었으면
				print "[ * ] Crash Tracking Start !!!", self.orig_file
				# 크래시 난 파일 복사
				shutil.copy(self.orig_file, self.tmp_file)
				# 트래킹하는 뮤테이션 함수 호출
				self.mutate_track()

			# 디버거 쓰레드 실행
			pydbg_thread = threading.Thread(target=self.start_debugger)
			pydbg_thread.setDaemon(0)
			pydbg_thread.start()

			while self.pid == None:
				time.sleep(0.5)

			# 모니터링 쓰레드 실행
			monitor_thread = threading.Thread(target=self.monitor_debugger)
			monitor_thread.setDaemon(0)
			monitor_thread.start()

			self.count +=1

	# 대상 어플리케이션을 실행시키는 디버거 쓰레드
	def start_ASDsvc_debugger(self):

		self.running_ads = True
		self.dbg_ads = pydbg()

		self.dbg_ads.set_callback(EXCEPTION_ACCESS_VIOLATION,self.check_accessv)
		cmd = "tasklist /FI \"IMAGENAME eq asdsvc.exe\" /FO LIST"
		pipe = subprocess.Popen(cmd,
		    shell=True,
		    stdin=subprocess.PIPE,
			stdout=subprocess.PIPE,
		    stderr=subprocess.PIPE)
		output, errors = pipe.communicate()
		pipe.stdin.close()
		if errors != "":
			print "error"
		else:
			self.pid_ads = output.split("\n")[2].split(" ")[-1]
			self.dbg_ads.attach(int(self.pid_ads,10))
			self.dbg_ads.run()
		print "running ads debugger"


	# 대상 어플리케이션을 실행시키는 디버거 쓰레드
	def start_debugger(self):

		self.running = True
		self.dbg = pydbg()

		pid = self.dbg.load(self.exe_path, "/manual_scan /target:" + self.tmp_dir + "\\" + self.orig_file.split("\\")[-1] )
		# print self.exe_path + "/manual_scan /target:" + self.tmp_dir + "\\" + self.orig_file.split("\\")[-1]
		self.pid = self.dbg.pid
		self.dbg.run()

	# 어플레킹션을 몇 초 동안 실행 되게 한 다음 종료시키는 모니터링 쓰레드 
	def monitor_debugger(self):

		counter = 0
		print "[*] waiting ",
		while counter < 3 and self.pid != None:
			time.sleep(1)
			print ".",
			counter += 1
		print "\n"

		if self.in_accessv_handler != True:
			tid = c_ulong(0)
			if windll.kernel32.GetHandleInformation(self.dbg.h_process, byref(tid)) :
				self.dbg.terminate_process()
			self.dbg.close_handle(self.dbg.h_process)
			
		else:
			while self.pid != None:
				time.sleep(0.5)
		
		while True :
			try :
				#os.remove(self.tmp_file)
				break
			except :
				time.sleep(0.2)
		self.in_accessv_handler = False
		self.running = False


	# 에러를 추적하고 정보를 저장하기 위한 접근 위반 핸들러 
	def check_accessv(self, dbg):
		
		# 트래킹 활성화 여부 체크
		if self.crash_tracking == False:

			# 중복된 크래시 인지 체크
			if self.dbg_ads.context.Eip in self.eip_list:
				print "\n[ x ] Duplicate Crash!!"
				self.in_accessv_handler = False
				self.dbg_ads.terminate_process()
				self.pid_ads = None

				return DBG_EXCEPTION_NOT_HANDLED

			# eip 리스트에 추가
			self.eip_list.append(self.dbg.context.Eip)

			# 트래킹 활성화
			self.crash_tracking = True
			self.in_accessv_handler = True
			
			print "\n[*] Woot! Handling an access violation!"
			print "[*] EIP : 0x%08x" % self.dbg.context.Eip
			
			crash_bin = utils.crash_binning.crash_binning()
			crash_bin.record_crash(dbg)
			self.crash = crash_bin.crash_synopsis()

			# 크래시 일 때 카운트정보를 작성한다.
			self.crash_count = self.count
			# 크래시 정보 로깅
			crash_fd = open("crash\\crash-%d.log" % self.count,"w")
			crash_fd.write(self.crash)
			crash_fd.close()

			# 원본 파일을 백업한다.
			shutil.copy(self.orig_file,"crash\\%d_orig%s" % (self.count,self.ext))

			self.dbg_ads.terminate_process()
			self.pid_ads = None

			return DBG_EXCEPTION_NOT_HANDLED

		# 트래킹 활성화 시 수행할 루틴 
		else:
			
			#접근위반 핸들러 활성화
			self.in_accessv_handler = True
			self.dbg.terminate_process()
			self.pid = None
			
			print "[+] crash Again!!"
			# 크래시 난 리스트를 뮤테이션 리스트에 넣는다.
			self.mutate_list = self.selected_list
			
			# 크래시가 나면 새로운 피봇 설정
			# self.pivot = self.mutate_list.index(random.choice(self.mutate_list))
			
			# 피봇이 처음이거나 끝이면 다시 설정
			# if self.pivot == 0 or self.pivot == len(self.mutate_list)-1:
			#	self.pivot = self.mutate_list.index(random.choice(self.mutate_list))
				
			self.check = False

			print "[+] Mutate list count -- %d" % len(self.mutate_list)

			 # 뮤테이션 리스트 원소의 갯수가 5개보다 적으면 수행 할 루틴
			if len(self.mutate_list) == 1:
				print "[ ^^ ] tracking Finished! %d -> %d" % (self.mutate_count, len(self.mutate_list))
				# 크래시 파일 백업
				shutil.copy(self.tmp_file, "crash\\crash_%d%s" % (self.crash_count,self.ext))

				# 로그 추가 기록
				f = open("crash\\crash_%d.log" % self.crash_count, 'a')
				f.write("\n\n---------------- Check this Offset!! ------------------\n\n")
				for i in self.mutate_list:
					f.write("offset : "+ hex(i[0])+", 0x"+i[1] + "\n" )
				f.write("\n\nEND")
				f.close()

				# 각종 변수 초기화
				self.crash_tracking = False
				self.crash_again = False
				self.crash_tracking_step = 0
				self.selected_list = []
				self.pivot = 0

			return DBG_EXCEPTION_NOT_HANDLED


	def mutate_file( self ):
		OLE_list = ["hwp", "doc", "ppt", "xls"]
		PE_list = ["exe"]
		COMP_list = ["zip", "gz", "7z", "rar"]

		print "[*] Selected file : %s" % self.orig_file
		ext = self.orig_file.split(".")[-1]

		if(ext in COMP_list):
		  #print self.sample_dir
		  #print self.tmp_dir
		  #print self.orig_file
		  fuzzer = COMP_fuzzer.COMP_FUZZ(self.sample_dir + "\\", self.tmp_dir+ "\\" + str(time.time()).replace(".", "") + "-", self.orig_file.split("\\")[-1])
		  fuzzer.Mutation()
		   
		if(ext in PE_list):
		  #print self.sample_dir
		  #print self.tmp_dir
		  #print self.orig_file
		  fuzzer = PE_fuzzer.PE_FUZZ(self.sample_dir+ "\\", self.tmp_dir+ "\\" + str(time.time()).replace(".", "") + "-", self.orig_file.split("\\")[-1])
		  fuzzer.Mutation()

		if(ext in OLE_list):
		  #print self.sample_dir
		  #print self.tmp_dir
		  #print self.orig_file
		  fuzzer = OLE_fuzzer.OLE_FUZZ(self.sample_dir+ "\\", self.tmp_dir+ "\\" + str(time.time()).replace(".", "") + "-", self.orig_file.split("\\")[-1])
		  fuzzer.Mutation()
		print "[*] Fin Fuzz"

	  # cmd = "call " + "\"C:\\Program Files\\AhnLab\\V3Lite30\\V3LMedic.exe\" /manual_scan /target:" + self.orig_file
	  # pipe = subprocess.Popen(cmd,
	  #   shell=True,
	  #   stdin=subprocess.PIPE,
	  #   stdout=subprocess.PIPE,
	  #   stderr=subprocess.PIPE)
	  # pipe.stdin.close()
	  # time.sleep(2)
		return

	def mutate_track( self ):
		"""
		# 트래킹이 처음 스탭일때(0) 수행
		if self.crash_tracking_step == 0:
			# 트래킹 카운트 초기화
			self.tracking_count = 0
			# 랜덤한 피봇 설정
			self.pivot= self.mutate_list.index(random.choice(self.mutate_list))
			# 피봇이 처음이거나 끝이면 다시 설정
			if self.pivot == 0 or self.pivot == len(self.mutate_list)-1:
				self.pivot = self.mutate_list.index(random.choice(self.mutate_list))
			# 트래킹 스탭 1로 설정
			self.crash_tracking_step = 1
		"""
		# 트래킹하는 카운트 증가
		self.tracking_count+=1
			
		pivot = len(self.mutate_list)/2

		# 트래킹 카운트가 비 정상이면 강제 종료(무한루프 방지)
		if self.tracking_count > 20:
			print "[T.T] tracking Fail... re-Try!"
			self.crash_tracking = False
			self.selected_list = []
			self.tracking_count = 0
			#eip 리스트를 비운다. (pop을 할까?)
			self.eip_list = []
			#트래킹 실패한 파일 삭제
			os.remove("crash\\%d_orig.hwp" % self.crash_count)
			os.remove("crash\\crash-%d.log" % self.crash_count)
			return
		
		# 피봇을 기준으로 좌우로 나눈다.
		left = self.mutate_list[:pivot]
		right = self.mutate_list[pivot:]

		# 리스트 선택
		if self.check == False:
			print "left"
			self.selected_list = left
			#체크 변수 토글
			self.check = True
		else:
			print "right"
			self.selected_list = right
			#체크 변수 토글
			self.check = False
			
		# 수정할 파일 오픈 
		f = open(self.tmp_file, 'r+b')
		
		#tmp 파일에 쓰기
		for i in self.selected_list:
			#print i[0], i[1]
			f.seek(i[0])
			f.write(chr(int(i[1][:2],16)) * (len(i[1])/2))
		f.close()


		
		return

if __name__ == "__main__":

  cmd = "mkdir C:\\fuzz\\in"
  os.system( cmd )
  cmd = "mkdir C:\\fuzz\\temp"
  os.system( cmd )

  print "[*] File Fuzzer."
  exe_path = ("C:\\Program Files\\AhnLab\\V3Lite30\\V3LMedic.exe")
		
  if exe_path is not None:
	fuzzer = file_fuzzer( exe_path)
	fuzzer.fuzz()
  else:
	"[+] Error!"
