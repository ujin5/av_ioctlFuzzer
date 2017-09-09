import os
import sys
import OLE_fuzzer
import PE_fuzzer
import COMP_fuzzer
import subprocess
import time

seed_dir = "C:\\fuzz\\in\\"
_out_dir = "C:\\fuzz\\out\\"

OLE_list = ["hwp", "doc", "ppt", "xls"]
PE_list = ["exe"]
COMP_list = ["zip", "gz", "7z", "rar"]


filelist = os.listdir(seed_dir)
i = 0
while True:
   out_dir = _out_dir + str(i) +"\\"
   cmd = "mkdir " + out_dir 
   os.system( cmd )
   print out_dir
   i += 1
   for filename in filelist:
      print "Fuzzing " + finename
      ext = filename.split(".")[1]
   
      if(ext in COMP_list):
         fuzzer = COMP_fuzzer.COMP_FUZZ(seed_dir, out_dir, filename)
         fuzzer.Mutation()
       
      if(ext in PE_list):
         fuzzer = PE_fuzzer.PE_FUZZ(seed_dir, out_dir, filename)
         fuzzer.Mutation()
       
      if(ext in OLE_list):
         fuzzer = OLE_fuzzer.OLE_FUZZ(seed_dir, out_dir, filename)
         fuzzer.Mutation()
   print "Fin Fuzz"
   # scanning by V3
   filenames = os.listdir( out_dir )
   os.system("taskkill /im V3LMedic.exe")
   print "scanning by V3"
   cmd = "call " + "\"C:\\Program Files\\AhnLab\\V3Lite30\\V3LMedic.exe\" /manual_scan /target:" + out_dir
   print cmd
   pipe = subprocess.Popen(cmd,
        shell=True,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE)
   pipe.stdin.close()
   time.sleep(2)
