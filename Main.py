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
import DOC_fuzzer
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
		self.filename			= ""
		self.ord_ads			= False
		self.pid_exe			 = None
		self.running_v3			= False
		self.running_ads		 = False
		self.running_cra		= False
		self.pid_ads			 = None
		self.dbg_ads			 = None

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
		sel_file = str(time.time()).replace(".", "") + "-" + str(file_num) + "-" + file_list[file_num]
		self.tmp_file = self.tmp_dir + "\\" + sel_file
		self.orig_file = self.sample_dir + "\\" + file_list[file_num]
		## shutil.copy(self.orig_file,  self.tmp_file)
		return

	# 에러를 추적하고 정보를 저장하기 위한 접근 위반 핸들러 
	def handler_access_violation(self, pydbg):

		self.running_cra = True

		print "\n[-] Access_violation Crash!!\n"
		print "[-] Woot! Handling an access violation!"
		print "[-] EIP : 0x%08x" % self.dbg_ads.context.Eip

		# eip 리스트에 추가
		self.eip_list.append(self.dbg_ads.context.Eip)

		# 트래킹 활성화
		# self.crash_tracking = True
		# self.in_accessv_handler = True

		crash_bin = utils.crash_binning.crash_binning()
		crash_bin.record_crash(self.dbg_ads)
		self.crash = crash_bin.crash_synopsis()

		# 크래시 일 때 카운트정보를 작성한다.
		self.crash_count = self.count

		# 크래시 정보 로깅
		crash_fd = open("C:\\fuzz\\crash\\" + self.tmp_file.split("\\")[-1] + "-%d.log" % self.count,"w")
		crash_fd.write(self.crash)
		crash_fd.close()
		
		# 원본 파일을 백업한다.
		shutil.copy(self.tmp_file, "C:\\fuzz\\crash\\" + self.tmp_file.split("\\")[-1].split(".")[0] + "-" + str(self.count) + "." + self.tmp_file.split(".")[-1] )

		self.dbg_ads.terminate_process()
		self.dbg_ads.close_handle(self.dbg_ads.h_process)
		self.dbg_ads.detach()
		self.pid_ads = None
		self.running_ads = False

		print "[*] Restart ASDsvc"

		self.running_ads = False
		restart_thread = threading.Thread(target=self.kill_ASDsvc)
		restart_thread.setDaemon(0)
		restart_thread.start()

		while self.running_ads == False:
			while self.running_v3 == False:
				time.sleep(0.5)
			time.sleep(10)
			print "kill v3"
			os.system("taskkill /F /IM v3lite.exe")		
			time.sleep(2)
		print "finzzzz"

		pydbg_ads_thread = threading.Thread(target=self.start_ASDsvc_debugger)
		pydbg_ads_thread.setDaemon(0)
		pydbg_ads_thread.start()

		print "[-]Fin save crash & restart ASDsvc"

		self.running_cra = False
		self.running = False

		return DBG_EXCEPTION_NOT_HANDLED


	def fuzz(self):
		
		self.file_picker_setting()

		# adssvc.exe에 디버거
		debugger_thread = threading.Thread(target=self.start_ASDsvc_debugger)
		debugger_thread.setDaemon(0)
		debugger_thread.start()



		while self.pid_ads == None:
			time.sleep(0.5)
		while 1:
			self.count +=1

			while self.running or self.running_cra:
				time.sleep(1)

			self.running = True

			print "[*] Starting Antivirus for iteration: %d" % self.count

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

			# 실행파일 쓰레드 실행
			pydbg_thread = threading.Thread(target=self.start_exe)
			pydbg_thread.setDaemon(0)
			pydbg_thread.start()

			'''
			# Attack ASDsvc.exe
			if self.count == 5:
				attack_thread = threading.Thread(target=self.attack_debugger)
				attack_thread.setDaemon(0)
				attack_thread.start()
			'''

			while self.running_cra:
				time.sleep(1)
			
			# 모니터링 쓰레드 실행
			monitor_thread = threading.Thread(target=self.monitor_exe)
			monitor_thread.setDaemon(0)
			monitor_thread.start()

			if (self.count % 100) == 99:
				time.sleep(5)

				print "[*] Restart ASDsvc"

				self.running_ads = False
				restart_thread = threading.Thread(target=self.kill_ASDsvc)
				restart_thread.setDaemon(0)
				restart_thread.start()

				while self.running_ads == False:
					while self.running_v3 == False:
						time.sleep(0.5)
					time.sleep(10)
					os.system("taskkill /F /IM v3lite.exe")		
					time.sleep(2)		

				pydbg_ads_thread = threading.Thread(target=self.start_ASDsvc_debugger)
				pydbg_ads_thread.setDaemon(0)
				pydbg_ads_thread.start()



	def kill_ASDsvc(self):
		print "[-] Start to kill process"
		while True:
			self.running_v3 = False
			os.system("taskkill /F /IM v3lmedic.exe")
			time.sleep(0.5)
			os.system("taskkill /F /IM asdsvc.exe")
			time.sleep(0.5)
			os.system("taskkill /F /IM v3lite.exe")
			time.sleep(3)
			self.running_v3 = True
			os.system( "\"C:\\Program Files\\AhnLab\\V3Lite30\\V3Lite.exe\"" )
			cmd = "tasklist /FI \"IMAGENAME eq v3lite.exe\" /FO LIST"
			pipe = self.wincmd(cmd)
			output1, errors1 = pipe.communicate()
			pipe.stdin.close()
			cmd = "tasklist /FI \"IMAGENAME eq asdsvc.exe\" /FO LIST"
			pipe = self.wincmd(cmd)
			output2, errors2 = pipe.communicate()
			pipe.stdin.close()
			if output2.split("\n")[0].encode("hex") == "0d":
				self.running_ads = True
				break;
		

	# 대상 어플리케이션을 실행시키는 디버거 쓰레드
	def start_ASDsvc_debugger(self):
		self.running_ads = True
		self.dbg_ads = pydbg()
		cmd = "tasklist /FI \"IMAGENAME eq asdsvc.exe\" /FO LIST"
		pipe = self.wincmd(cmd)
		output, errors = pipe.communicate()
		pipe.stdin.close()
		if errors != "":
			print "[-] Error on start"
		else:
			self.pid_ads = output.split("\n")[2].split(" ")[-1]
			self.dbg_ads.set_callback(EXCEPTION_ACCESS_VIOLATION, self.handler_access_violation ) 
			self.dbg_ads.attach(int(self.pid_ads,10))
			print "[+] Attach debugger to ASDsvc : " + str(self.pid_ads)
			self.dbg_ads.run()

	def attack_debugger(self):
		print "[!] Start attack : " + str( self.dbg_ads.pid )
		# self.dbg_ads.suspend_all_threads()
		for thread_id in self.dbg_ads.enumerate_threads():
			thread_handle  = self.dbg_ads.open_thread(thread_id)
			thread_context = self.dbg_ads.get_thread_context(thread_handle)
			# print "Eip = 0x%08x" % thread_context.Eip
			thread_context.Eip=0xdeadbeef
			self.dbg_ads.set_thread_context(thread_context,0,thread_id)
			thread_context = self.dbg_ads.get_thread_context(thread_handle)
			# print "new Eip = 0x%08x" % thread_context.Eip
		# self.dbg_ads.resume_all_threads()
		# pydbg.debug_event_loop(self.dbg_ads)
		print "[!] Fin attack : "

	# 대상 어플리케이션을 실행
	def start_exe(self):

		self.running = True

		while True :
			cmd = "\"" + self.exe_path + "\" /manual_scan /target:" + self.tmp_file
			# print cmd
			pipe = self.wincmd(cmd)
			pipe.stdin.close()
			cmd = "tasklist /FI \"IMAGENAME eq v3lmedic.exe\" /FO LIST"
			pipe = self.wincmd(cmd)
			output, errors = pipe.communicate()
			pipe.stdin.close()
			if errors == "":
				self.pid_exe = output.split("\n")[2].split(" ")[-1]
				break
			else:
				print "no medic"


		# 어플레킹션을 몇 초 동안 실행 되게 한 다음 종료시키는 모니터링 쓰레드 
	def monitor_exe(self):

		while self.pid_exe == None:
			time.sleep(0.5)

		counter = 0
		print "[*] waiting ",
		while counter < 3 and self.pid_exe != None:
			time.sleep(1)
			print ".",
			counter += 1
		print "\n"

		#if self.in_accessv_handler != True:
		os.system("taskkill /F /IM v3lmedic.exe")
		#else:
		#	while self.pid_exe != None:
		#		time.sleep(0.5)
		
		self.in_accessv_handler = False
		self.running = False

	def mutate_file( self ):
		DOC_list = ["hwp", "doc", "ppt", "xls", "pdf", "chm", "rtf"]
		PE_list = ["exe"]
		COMP_list = ["zip", "gz", "7z", "rar"]

		print "[*] Selected file : %s" % self.orig_file
		ext = self.orig_file.split(".")[-1]
		
		if(ext in COMP_list):
		  #print self.sample_dir
		  #print self.tmp_dir+ "\\" + self.tmp_file.split("\\")[-1].split("-")[0]
		  #print self.tmp_file
		  fuzzer = COMP_fuzzer.COMP_FUZZ(self.sample_dir + "\\", self.tmp_dir+ "\\" + self.tmp_file.split("\\")[-1].split("-")[0] + "-" + self.tmp_file.split("\\")[-1].split("-")[1] + "-" , self.tmp_file.split("-")[-1])
		  fuzzer.Mutation()
		   
		if(ext in PE_list):
		  #print self.sample_dir
		  #print self.tmp_dir
		  #print self.orig_filee
		  #print self.tmp_file
		  fuzzer = PE_fuzzer.PE_FUZZ(self.sample_dir + "\\", self.tmp_dir+ "\\" + self.tmp_file.split("\\")[-1].split("-")[0] + "-" + self.tmp_file.split("\\")[-1].split("-")[1] + "-", self.tmp_file.split("-")[-1])
		  fuzzer.Mutation()

		if(ext in DOC_list):
		  #print self.sample_dir
		  #print self.tmp_dir
		  #print self.orig_file
		  fuzzer = DOC_fuzzer.DOC_FUZZ(self.sample_dir + "\\", self.tmp_dir+ "\\" + self.tmp_file.split("\\")[-1].split("-")[0] + "-" + self.tmp_file.split("\\")[-1].split("-")[1] + "-", self.tmp_file.split("-")[-1])
		  fuzzer.Mutation()
		print "[*] Fin Fuzz"

		return


if __name__ == "__main__":

	os.system( "mkdir C:\\fuzz\\in C:\\fuzz\\temp C:\\fuzz\\crash" )

	print "[*] File Fuzzer."
	exe_path = ("C:\\Program Files\\AhnLab\\V3Lite30\\V3LMedic.exe")
		
	if exe_path is not None:
		fuzzer = file_fuzzer( exe_path)
		fuzzer.fuzz()
	else:
		"[+] Error!"
