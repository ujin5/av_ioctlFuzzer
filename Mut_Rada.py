# -*- coding: utf-8 -*-
import utils
import threading
import os
import sys
import subprocess

def wincmd(cmd):
	return subprocess.Popen(cmd,
		shell=True,
		stdin=subprocess.PIPE,
		stdout=subprocess.PIPE,
		stderr=subprocess.PIPE)

class radamsa(object):
	def __init__(self, data):
		self.data = data
		print "init : " + self.data

	def mutate(self):
		self.data
		cmd ="dir"
		print cmd
		pipe = wincmd(cmd)
		output, errors = pipe.communicate()
		pipe.stdin.close()
		print output
		return self.data



'''
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
'''
