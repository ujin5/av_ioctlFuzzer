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

	def mutate(self):
		cmd ="echo " + self.data + "| radamsa"
		# print cmd
		pipe = wincmd(cmd)
		output, errors = pipe.communicate()
		pipe.stdin.close()
		# print output
		return self.data
