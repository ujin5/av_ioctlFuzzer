import os
import sys
import time

dirname = "c:\\fuzz\\out"

filenames = os.listdir( dirname )

for filename in filenames:
    print "scanning by V3"
    full_filename = os.path.join(dirname, filename)
    cmd = "\"C:\\Program Files\\AhnLab\\V3Lite30\\V3LMedic.exe\" /manual_scan /target:" + dirname
    print cmd
    os.system( cmd )