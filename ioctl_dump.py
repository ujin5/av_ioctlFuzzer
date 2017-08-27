import pickle
import driverlib
from immlib import *

def main(args):
    ioctl_list = []
    device_list = []

    imm = Debugger()
    driver = driverlib.Driver()

    ioctl_list = drvier.getIOCTLCodes()
    if not len(ioctl_list):
        return "[*] ERROR! Couldn't find any IOCTL codes."

    device_list = driver.getDeviceNames()
    if not len(device_list):
        return "[*] ERROR! Couldn't find any device names."

    master_list = {}
    master_list["ioctl_list"] = ioctl_list
    master_list["device_list"] = device_list

    filename = "%s.fuzz" % imm.getDebuggedName()
    fd = open(filename, "wb")

    pickle.dump(master_list, fd)
    fd.close()

    return "[*] Success! Saved IOCTL codes and device names to %s" % filename

