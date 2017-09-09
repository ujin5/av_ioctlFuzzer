import os
import sys
import OLE_fuzzer
import PE_fuzzer
import COMP_fuzzer
import subprocess
import time

seed_dir = "C:\\fuzz\\in\\"
out_dir = "C:\\fuzz\\out\\"

OLE_list = ["hwp", "doc", "ppt", "xls"]
PE_list = ["exe"]
COMP_list = ["zip", "gz", "7z", "rar"]
filelist = os.listdir(seed_dir)
pre_dir = "C:\\fuzz\\out\\"
while True:
	print "# Start Fuzz"
	for filename in filelist:
		of_dir = out_dir + str(time.time()).replace(".", "") + "-"
		print of_dir
		print "      Fuzzing " + of_dir + filename
		ext = filename.split(".")[1]
   
		if(ext in COMP_list):
			fuzzer = COMP_fuzzer.COMP_FUZZ(seed_dir, of_dir, filename)
			fuzzer.Mutation()
       
		if(ext in PE_list):
			fuzzer = PE_fuzzer.PE_FUZZ(seed_dir, of_dir, filename)
			fuzzer.Mutation()

		if(ext in OLE_list):
			fuzzer = OLE_fuzzer.OLE_FUZZ(seed_dir, of_dir, filename)
			fuzzer.Mutation()
		print "# Fin Fuzz"
		
		# checking kill vemedic.exe
		filenames = os.listdir( out_dir )
		cmd = "taskkill /im V3LMedic.exe"
		# print cmd
		pipe = subprocess.Popen(cmd,
		    shell=True,
		    stdin=subprocess.PIPE,
			stdout=subprocess.PIPE,
		    stderr=subprocess.PIPE)
		output, errors = pipe.communicate()
		print "# Kill V3LMedic.exe"
		if errors != "":
			print "# Error in " + pre_dir
			fw = open( pre_dir + "-log.txt", 'w')
			fw.write("Crash on V3Medic.exe\n")
			fw.write( errors )
			fw.close()
		pipe.stdin.close()

		print "# Scanning by V3"
		cmd = "call " + "\"C:\\Program Files\\AhnLab\\V3Lite30\\V3LMedic.exe\" /manual_scan /target:" + of_dir + filename
		# print cmd
		pipe = subprocess.Popen(cmd,
			shell=True,
			stdin=subprocess.PIPE,
			stdout=subprocess.PIPE,
			stderr=subprocess.PIPE)
		pipe.stdin.close()
		time.sleep(2)
		pre_dir = of_dir + filename
