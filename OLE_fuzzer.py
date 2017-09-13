# -*- coding:utf-8 -*-
# Module : OLE_fuzzer.py

#------------------------------------------------------------
# 설명 : OLE 구조를 가지는 hwp, doc, ppt, xls 확장자를 가진 파일을 뮤테이션시킨다.
#------------------------------------------------------------
import os
from pyZZUF import *
from random import choice
import shutil

class OLE_FUZZ:

    def __init__(self, seed_dir, out_dir, filename):
        self.SEED_DIR = seed_dir
        self.OUT_DIR = out_dir
        self.FILENAME = filename
        self.new_data = ""
        self.fp = open(self.SEED_DIR + self.FILENAME, "rb")

    #------------------------------------------------------------
    # 함수명 : Mutation
    # 설  명 : OLE 구조를 가지는 파일을 뮤테이션시킨 후 파일에 쓴다.
    #------------------------------------------------------------
    def Mutation(self):

        data = self.fp.read()
        
        # 확장자 확인하기
        ext = self.target.split(".")[1]
        #print "file extension : %s" % ext
        
        # 확장자별로 맞춤형 mutation하기
        if ext == "hwp" or ext == "xls":
            self.new_data = self.fuzz_without_sub_header(data)
        elif ext == "doc" or ext == "ppt":
            self.new_data = self.fuzz_with_sub_header(data)
        else:
            self.new_data = None
        
        # mutation된 값을 파일에 쓰기
        if self.new_data != None:
            fp = open(self.target, "wb")
            fp.write(self.new_data)

    #------------------------------------------------------------
    # 함수명 : fuzz_without_sub_header
    # 설  명 : V3에서 sub_header를 검사하지 않는 파일을 뮤테이션시킨다.
    # 인자값 : data : 뮤테이션시킬 데이터
    # 반환값 : rdata : 뮤테이션시킨 데이터
    #------------------------------------------------------------
    def fuzz_without_sub_header(self, data):

        signature = data[0:8]

        rdata = ""
        rdata += signature
        rdata += pyZZUF(data[8:]).mutate().tostring()
        
        return rdata

    #------------------------------------------------------------
    # 함수명 : fuzz_with_sub_header
    # 설  명 : V3에서 sub_header를 검사하는 파일을 뮤테이션시킨다.
    # 인자값 : data : 뮤테이션시킬 데이터
    # 반환값 : rdata : 뮤테이션시킨 데이터
    #------------------------------------------------------------
    def fuzz_with_sub_header(self, data):

        signature = data[0:8]

        rdata = ""
        rdata += signature
        rdata += pyZZUF(data[8:512]).mutate().tostring()

        sub_signature = data[512:516]

        rdata += sub_signature
        rdata += pyZZUF(data[516:]).mutate().tostring()

        return rdata
