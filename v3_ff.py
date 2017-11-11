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
import subprocess
import re
import Mut_Rada


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
		self.notmp_dir			 = "C:\\fuzz\\notemp"
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
		self.running_exe		= False
		self.pid_ads			 = None
		self.dbg_ads			 = None
		self.ex_dbg		= False
		self.ex_start_ASDsvc = False
		self.folder_list = None

	def wincmd(self, cmd):
		return subprocess.Popen(cmd,
			shell=True,
			stdin=subprocess.PIPE,
			stdout=subprocess.PIPE,
			stderr=subprocess.PIPE)

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

		# 크래시 정보 self.crash에 저장
		crash_bin = utils.crash_binning.crash_binning()
		crash_bin.record_crash(self.dbg_ads)
		self.crash = crash_bin.crash_synopsis()

		# 크래시 일 때 카운트정보를 작성한다.
		self.crash_count = self.count

		# 크래시 정보 로깅
		crash_fd = open("C:\\fuzz\\crash\\" + str(time.time()).replace(".", "") + ".log","w")
		crash_fd.write(self.crash)
		crash_fd.close()
		
		print "1"

		# 크래시 파일을 탐색
		print "[*]Finding"
		while True:
			fnum = self.check_folder()
			print ".",
			time.sleep(0.5)
			if(fnum != -1):
				break

		# 디버거 종료
		print "[-]Terminate Debugger"
		self.dbg_ads.terminate_process()
		self.dbg_ads.close_handle(self.dbg_ads.h_process)
		self.dbg_ads.detach()
		self.pid_ads = None


		pydbg_ads_thread = threading.Thread(target=self.start_ASDsvc)
		pydbg_ads_thread.setDaemon(0)
		pydbg_ads_thread.start()
		while self.ex_start_ASDsvc:
			time.sleep(1)
		self.running_exe = False
		os.system("taskkill /F /IM v3lite.exe")	

		print "[-]Backup Crash File"
		tnum = 0
		while tnum < fnum:
			shutil.move(self.tmp_dir + "\\" + self.folder_list[tnum] , self.notmp_dir + "\\" + self.folder_list[tnum])
			tnum += 1
		shutil.move(self.tmp_dir + "\\" + self.folder_list[fnum], "C:\\fuzz\\crash\\" + str(time.time()).replace(".", "") + self.folder_list[fnum])

		print "[+]Fin to Exception handle"

		self.running_cra = False
		self.running = False

		return DBG_EXCEPTION_NOT_HANDLED


	def fuzz(self):

		'''
		디버거를 붙인다.
		temp폴더를 모두 검사한다.
		크래시가 나면 폴더 이름을 바꾸면서 에러가 나는 폴더 탐색 후 탐색 된 폴더는 백업 후에 다시 처음으로 ㄱㄱ


		'''
		while True:

			while self.running_cra:
				time.sleep(1)

			# adssvc.exe에 디버거
			debugger_thread = threading.Thread(target=self.start_ASDsvc_debugger)
			debugger_thread.setDaemon(0)
			debugger_thread.start()

			while self.ex_dbg:
				print "wait"
				time.sleep(1)
			time.sleep(3)
			# asd에 디버거 붙었어

			# 탐색기 검사를 시작
			pydbg_thread = threading.Thread(target=self.start_exe)
			pydbg_thread.setDaemon(0)
			pydbg_thread.start()

			self.running_exe = True

			while self.running_exe:
				time.sleep(1)


	def start_ASDsvc(self):
		# asdsvc 살려 내기
		self.ex_start_ASDsvc = True
		while not self.check_process("ASDsvc.exe"):
			self.running_exe = False
			os.system("taskkill /F /IM v3lmedic.exe")
			time.sleep(0.5)
			os.system("taskkill /F /IM asdsvc.exe")
			time.sleep(0.5)
			os.system("taskkill /F /IM v3lite.exe")
			time.sleep(3)
			self.ex_start_ASDsvc = False
			os.system( "\"C:\\Program Files\\AhnLab\\V3Lite30\\V3Lite.exe\"" )

	def check_folder(self):
		#어떤 폴더 사용중인지 확인 함수
		self.folder_list = os.listdir(self.tmp_dir)
		folder_num = -1
		for folder in self.folder_list:
			folder_num += 1
			try:
				os.rename(self.tmp_dir +"\\"+ folder, self.tmp_dir + "\\"+ folder + str(folder_num))
			except:
				print "[*]Crash is here in " + self.tmp_dir + "\\" + folder
				return folder_num
			os.rename(self.tmp_dir + "\\"+ folder + str(folder_num), self.tmp_dir +"\\"+ folder)

		return -1

	def check_process(self, id):
		# asdsvc가 있는지 확인
		cmd = "tasklist /FI \"IMAGENAME eq " + id + "\" /FO LIST"
		pipe = self.wincmd(cmd)
		output, errors = pipe.communicate()
		if len(output) < 70:
			return False	# 없으면 false
		else:
			return output.split("\n")[2].split(" ")[-1]		# 잘실행 중이면 pid 반환
		pipe.stdin.close()

	# 대상 어플리케이션을 실행시키는 디버거 쓰레드
	def start_ASDsvc_debugger(self):
		self.ex_dbg = True
		self.dbg_ads = pydbg()
		# asdsvc가 있는지 확인
		while True:
			output = self.check_process("ASDsvc.exe")
			print "out : " + str(output)
			if not output:
				# asd죽어 있는거야
				print "[-] ASDsvc is dead, Starting ASDsvc"
				pydbg_ads_thread = threading.Thread(target=self.start_ASDsvc)
				pydbg_ads_thread.setDaemon(0)
				pydbg_ads_thread.start()
				while self.ex_start_ASDsvc:
					time.sleep(1)
				os.system("taskkill /F /IM v3lite.exe")	
				continue
			else:
				# asd 잘 살아 있으면
				self.pid_ads = str(output)
				self.dbg_ads.set_callback(EXCEPTION_ACCESS_VIOLATION, self.handler_access_violation ) 
				self.dbg_ads.attach(int(self.pid_ads, 10))
				print "[+] Attach debugger to ASDsvc : " + str(self.pid_ads)
				self.ex_dbg = False
				self.dbg_ads.run()
				break


	# 대상 어플리케이션을 실행
	def start_exe(self):
		while True :
			cmd = "\"" + self.exe_path + "\" /manual_scan /target:" + self.tmp_dir
			print cmd
			pipe = self.wincmd(cmd)
			pipe.stdin.close()
			time.sleep(1)
			output = self.check_process("v3lmedic.exe")
			if output != False:
				self.running_exe == True
				self.pid_exe = output
				break
			else:
				print "[-]Restart medic"

if __name__ == "__main__":

	os.system( "mkdir C:\\fuzz\\in C:\\fuzz\\temp C:\\fuzz\\crash C:\\fuzz\\notemp" )

	print "[*] File Fuzzer for V3."
	exe_path = ("C:\\Program Files\\AhnLab\\V3Lite30\\V3LMedic.exe")
	
	if exe_path is not None:
		fuzzer = file_fuzzer( exe_path)
		fuzzer.fuzz()
	else:
		"[+] Error!"