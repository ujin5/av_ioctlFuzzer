import os
fpath = "C:\\fuzz\\in\\"

for name in os.listdir(fpath):
    name_r = name.replace("-", "_")
    os.rename(fpath + name, fpath + name_r)
    print name + " >> " + name_r