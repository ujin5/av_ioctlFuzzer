import os
import OLE_fuzzer
import PE_fuzzer
import COMP_fuzzer

seed_dir = "C:\\Users\\JungUn\\Desktop\\seedfolder\\"
out_dir = "C:\\Users\\JungUn\\Desktop\\outfolder\\"

OLE_list = ["hwp", "doc", "ppt", "xls"]
PE_list = ["exe"]
COMP_list = ["zip", "gz", "7z", "rar"]


filelist = os.listdir(seed_dir)

while True:

	for filename in filelist:

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
