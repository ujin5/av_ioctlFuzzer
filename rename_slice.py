import os
fpath = "C:\\fuzz\\in\\"

for name in os.listdir(fpath):
    name_r = name.split("seed")[-1]
    os.rename(fpath + name, fpath + "seed" + name_r)
    print name + " >> " + name_r